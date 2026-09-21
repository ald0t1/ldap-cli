package directory

import (
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"

	"github.com/aldo/ldap-cli/internal/config"
)

// casAttempts bounds the compare-and-swap retry loop when several runs race
// for the counter entry.
const casAttempts = 5

// idSpec describes one id space: where to scan, what to count, and the
// optional counter entry that hands numbers out.
type idSpec struct {
	label       string // "uid" or "gid", for messages
	rng         config.Range
	baseDN      string
	objectClass string
	attr        string // uidNumber or gidNumber
}

func uidSpec(p *config.Profile) idSpec {
	return idSpec{label: "uid", rng: p.UID, baseDN: p.UserBaseDN, objectClass: "posixAccount", attr: "uidNumber"}
}

func gidSpec(p *config.Profile) idSpec {
	return idSpec{label: "gid", rng: p.GID, baseDN: p.GroupBaseDN, objectClass: "posixGroup", attr: "gidNumber"}
}

// AllocateUID reserves the next free uidNumber.
func (c *Client) AllocateUID() (int, error) {
	return allocate(c.Conn, uidSpec(c.Profile))
}

// AllocateGID reserves the next free gidNumber.
func (c *Client) AllocateGID() (int, error) {
	return allocate(c.Conn, gidSpec(c.Profile))
}

// PeekUID reports the uidNumber a scan would hand out, without reserving it.
// Used by --dry-run, which must not write.
func (c *Client) PeekUID() (int, error) {
	spec := uidSpec(c.Profile)
	floor, err := scanFloor(c.Conn, spec)
	if err != nil {
		return 0, err
	}
	return checkRange(floor, spec)
}

// allocate picks the next id for a spec.
//
// The directory is always scanned, and the scan result is a floor. When a
// counter entry is configured it is consulted too and claimed atomically, but
// it can only ever move the answer up. That combination is what makes this
// safe against the two things that actually go wrong in practice: accounts
// created outside this tool (which the counter knows nothing about), and a
// counter that was reset or restored from an older backup (which would
// otherwise reissue live ids).
func allocate(conn Conn, spec idSpec) (int, error) {
	floor, err := scanFloor(conn, spec)
	if err != nil {
		return 0, err
	}

	if spec.rng.NextDN == "" {
		return checkRange(floor, spec)
	}

	entry, err := searchOne(conn, spec.rng.NextDN, spec.rng.NextAttr)
	if err != nil {
		return 0, fmt.Errorf("read %s counter %s: %w", spec.label, spec.rng.NextDN, err)
	}
	if entry == nil {
		// Configured but not yet created. Scanning still gives a correct
		// answer, so this is a note rather than a failure.
		return checkRange(floor, spec)
	}

	return claimCounter(conn, spec, entry, floor)
}

// claimCounter reserves an id via compare-and-swap on the counter entry.
func claimCounter(conn Conn, spec idSpec, entry *ldap.Entry, floor int) (int, error) {
	current := entry.GetAttributeValue(spec.rng.NextAttr)

	for attempt := 1; ; attempt++ {
		counter, err := strconv.Atoi(current)
		if err != nil {
			return 0, fmt.Errorf("%s counter %s has non-numeric %s %q",
				spec.label, spec.rng.NextDN, spec.rng.NextAttr, current)
		}

		candidate := counter
		if floor > candidate {
			candidate = floor
		}
		if _, err := checkRange(candidate, spec); err != nil {
			return 0, err
		}

		// A single modify carrying both the delete of the old value and the
		// add of the new one is applied atomically by the server, so a racing
		// run either wins outright or fails and retries. Bare replace would
		// let two runs hand out the same id.
		mod := ldap.NewModifyRequest(spec.rng.NextDN, nil)
		mod.Delete(spec.rng.NextAttr, []string{current})
		mod.Add(spec.rng.NextAttr, []string{strconv.Itoa(candidate + 1)})

		if err := conn.Modify(mod); err == nil {
			return candidate, nil
		} else if attempt >= casAttempts {
			return 0, fmt.Errorf("could not claim an %s from counter %s after %d attempts "+
				"(another run may be provisioning concurrently): %w",
				spec.label, spec.rng.NextDN, casAttempts, err)
		}

		// Lost the race. Re-read and try again with the winner's value.
		fresh, err := searchOne(conn, spec.rng.NextDN, spec.rng.NextAttr)
		if err != nil {
			return 0, fmt.Errorf("re-read %s counter %s: %w", spec.label, spec.rng.NextDN, err)
		}
		if fresh == nil {
			return 0, fmt.Errorf("%s counter %s disappeared mid-allocation", spec.label, spec.rng.NextDN)
		}
		current = fresh.GetAttributeValue(spec.rng.NextAttr)
	}
}

// scanFloor returns the lowest id that is certainly free according to the
// directory itself: one past the highest in-range id in use, or the range
// minimum when nothing is in use.
func scanFloor(conn Conn, spec idSpec) (int, error) {
	filter := fmt.Sprintf("(&(objectClass=%s)(%s>=%d)(%s<=%d))",
		ldap.EscapeFilter(spec.objectClass),
		spec.attr, spec.rng.Min,
		spec.attr, spec.rng.Max)

	req := ldap.NewSearchRequest(
		spec.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{spec.attr}, nil,
	)

	res, err := searchAll(conn, req)
	if err != nil {
		return 0, fmt.Errorf("scan %s under %s: %w", spec.attr, spec.baseDN, err)
	}

	highest := 0
	for _, entry := range res.Entries {
		for _, raw := range entry.GetAttributeValues(spec.attr) {
			n, err := strconv.Atoi(raw)
			if err != nil {
				// A malformed id elsewhere in the tree should not stop
				// provisioning; it simply cannot raise the floor.
				continue
			}
			if n > highest {
				highest = n
			}
		}
	}

	if highest == 0 {
		return spec.rng.Min, nil
	}
	return highest + 1, nil
}

// checkRange confirms an id is inside the configured range.
func checkRange(id int, spec idSpec) (int, error) {
	if id > spec.rng.Max {
		return 0, fmt.Errorf("%s range %d-%d is exhausted (next would be %d); widen %s.max in the profile",
			spec.label, spec.rng.Min, spec.rng.Max, id, spec.label)
	}
	if id < spec.rng.Min {
		return spec.rng.Min, nil
	}
	return id, nil
}
