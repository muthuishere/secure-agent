package detect

import "testing"

const gh = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func TestTokenDoesNotSwallowTheNextWord(t *testing.T) {
	// Owner call, 2026-09-27: a token-shaped run is never an ordinary word,
	// so over-capture beats a leak — a run with the next word glued on is
	// captured whole (using it just fails auth; refusing would leak it).
	text := "abc " + gh + "abc " + gh
	hits := Find(text, nil)
	if len(hits) != 2 || hits[0].Value != gh+"abc" || hits[1].Value != gh {
		t.Fatalf("glued run: %+v", hits)
	}
	if hits := Find("x "+gh+" y "+gh, nil); len(hits) != 2 || hits[0].Value != gh || hits[1].Value != gh {
		t.Fatalf("two clean tokens: %+v", hits)
	}
}

func TestVaultValueWinsOverPattern(t *testing.T) {
	hits := Find("use "+gh, map[string]string{"MY_GH": gh})
	if len(hits) != 1 || hits[0].Name != "MY_GH" || !hits[0].Known {
		t.Fatalf("%+v", hits)
	}
}

func TestAssignmentNamesItself(t *testing.T) {
	hits := Find("DB_PASSWORD=hunter2hunter2", nil)
	if len(hits) != 1 || hits[0].Name != "DB_PASSWORD" || hits[0].Value != "hunter2hunter2" {
		t.Fatalf("%+v", hits)
	}
	if hits := Find("DB_PASSWORD={{DB_PASSWORD}}", nil); len(hits) != 0 {
		t.Fatalf("placeholder captured: %+v", hits)
	}
}

func TestReplace(t *testing.T) {
	text := "a " + gh + " b"
	if got := Replace(text, Find(text, nil)); got != "a {{GITHUB_TOKEN}} b" {
		t.Fatal(got)
	}
}

func TestGithubLongerThanCanonical(t *testing.T) {
	// Real-world shapes are not pinned to the canonical 36: truncated pastes,
	// fakes, fine-grained variants. A token-shaped run is never an ordinary
	// word — owner call, 2026-09-27 — so the run is open-ended at the top.
	long := gh + "ab" // 38
	if hits := Find("my key is "+long, nil); len(hits) != 1 || hits[0].Value != long {
		t.Fatalf("38-char: %+v", hits)
	}
	// letter-glued is captured whole too, for the same reason
	glued := long + "x"
	if hits := Find("key="+glued, nil); len(hits) != 1 || hits[0].Value != glued {
		t.Fatalf("letter-glued: %+v", hits)
	}
}

// The live miss, 2026-09-27: "my key is gk_…" went to the agent raw — no
// prefix rule knows gk_, and "key is" was not a cue.
func TestPhraseIntroducedValue(t *testing.T) {
	cases := []struct{ text, name, value string }{
		{"my key is gk_hnjdfhjhdjfhdjfhjdhfd", "API_KEY", "gk_hnjdfhjhdjfhdjfhjdhfd"},
		{"token: abcd1234efgh5678", "TOKEN", "abcd1234efgh5678"}, // the NAME: value rule wins,
		{"the password = Tr0ub4dor&3xyz", "PASSWORD", "Tr0ub4dor&3xyz"},
		{"api key is `vnd-live-00aa11bb22cc`", "API_KEY", "vnd-live-00aa11bb22cc"},
		{"Secret was abcdefghijklmnopqrstuv", "SECRET", "abcdefghijklmnopqrstuv"},
	}
	for _, c := range cases {
		hits := Find(c.text, nil)
		if len(hits) != 1 || hits[0].Name != c.name || hits[0].Value != c.value {
			t.Errorf("%q: %+v", c.text, hits)
		}
	}
	// prose after the cue is not a credential
	for _, text := range []string{
		"the key is important here",
		"my password is incorrect",
		"the token is expiredalready", // 19 letters, no digit/_/-
		"key is {{API_KEY}} already",
	} {
		if hits := Find(text, nil); len(hits) != 0 {
			t.Errorf("%q captured: %+v", text, hits)
		}
	}
}
