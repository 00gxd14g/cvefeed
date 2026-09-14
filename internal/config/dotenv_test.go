package config

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// The stack is configured by a .env that compose reads and the command did not.
// Someone who runs `make up` and then `cvefeed scan` in the same directory hits
// the gap between the file's password and the built-in default, and the only
// way past it was to compose the DSN by hand every session.
func TestDotenvSuppliesTheDSNTheStackIsUsing(t *testing.T) {
	dir := t.TempDir()
	writeEnv(t, dir, "POSTGRES_USER=alice\nPOSTGRES_PASSWORD=s3cret\nPOSTGRES_DB=corpus\n")

	env := loadDotenv(dir)
	if got := env["POSTGRES_PASSWORD"]; got != "s3cret" {
		t.Fatalf("password = %q", got)
	}
	dsn := dsnFromDotenv(env)
	want := "postgres://alice:s3cret@localhost:5432/corpus?sslmode=disable"
	if dsn != want {
		t.Errorf("dsn = %q, want %q", dsn, want)
	}
}

// The command runs outside the stack, so the host is localhost — not the
// compose service name, which resolves only inside the network.
func TestTheDSNPointsAtLocalhostNotTheComposeServiceName(t *testing.T) {
	dsn := dsnFromDotenv(map[string]string{"POSTGRES_PASSWORD": "x"})
	if got := dsn; got == "" {
		t.Fatal("no dsn built")
	}
	if want := "@localhost:5432/"; !contains(dsn, want) {
		t.Errorf("dsn = %q, want it to contain %q", dsn, want)
	}
}

// A real environment variable is a deliberate act and outranks a file.
func TestAnExplicitVariableBeatsTheFile(t *testing.T) {
	dir := t.TempDir()
	writeEnv(t, dir, "CVEFEED_DATABASE_URL=postgres://from-file/db\n")
	t.Setenv("CVEFEED_DATABASE_URL", "postgres://from-env/db")

	applyDotenv(loadDotenv(dir))
	if got := os.Getenv("CVEFEED_DATABASE_URL"); got != "postgres://from-env/db" {
		t.Errorf("CVEFEED_DATABASE_URL = %q, want the environment's value", got)
	}
}

func TestDotenvIsFoundFromASubdirectory(t *testing.T) {
	dir := t.TempDir()
	writeEnv(t, dir, "POSTGRES_PASSWORD=found\n")
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := loadDotenv(sub)["POSTGRES_PASSWORD"]; got != "found" {
		t.Errorf("password = %q; the file one directory up was not found", got)
	}
}

func TestDotenvParsesTheShapesPeopleWrite(t *testing.T) {
	dir := t.TempDir()
	writeEnv(t, dir, `# a comment
POSTGRES_USER=bob

export POSTGRES_DB=things
POSTGRES_PASSWORD="quoted value"
CVEFEED_API_TOKEN='single'
EMPTY=
BAD LINE
`)
	env := loadDotenv(dir)
	for k, want := range map[string]string{
		"POSTGRES_USER":     "bob",
		"POSTGRES_DB":       "things",
		"POSTGRES_PASSWORD": "quoted value",
		"CVEFEED_API_TOKEN": "single",
		"EMPTY":             "",
	} {
		if got := env[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if _, ok := env["BAD LINE"]; ok {
		t.Error("a line with no = was read as a setting")
	}
}

// compose reads `$` as the start of an interpolation, so a password with a
// dollar sign in it is written `$$` — the shipped .env.example says so — and
// the database is created with the single-dollar password compose produces.
// A reader that keeps the doubled form composes a DSN with a password the
// server has never seen. Single quotes are literal in compose, `$$` included.
func TestDotenvUndoublesTheComposeDollarEscape(t *testing.T) {
	dir := t.TempDir()
	writeEnv(t, dir, `POSTGRES_PASSWORD=pa$$word
DOUBLE="a$$b$$c"
SINGLE='lit$$eral'
TRAILING=x$$ # comment
`)
	env := loadDotenv(dir)
	for k, want := range map[string]string{
		"POSTGRES_PASSWORD": "pa$word",
		"DOUBLE":            "a$b$c",
		"SINGLE":            "lit$$eral",
		"TRAILING":          "x$",
	} {
		if got := env[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func writeEnv(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// The .env ships a DSN whose host is the compose service name, which resolves
// inside the network and nowhere else. The command runs outside it, so that
// host has to be redirected — while a host the operator chose deliberately, a
// managed database or another machine, must be left exactly as written.
func TestAComposeServiceNameIsRedirectedAndARealHostIsNot(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "the shipped .env, written for inside the network",
			env: map[string]string{
				"CVEFEED_DATABASE_URL": "postgres://cvefeed:local-dev-password@postgres:5432/cvefeed?sslmode=disable",
				"POSTGRES_PASSWORD":    "local-dev-password",
			},
			want: "postgres://cvefeed:local-dev-password@localhost:5432/cvefeed?sslmode=disable",
		},
		{
			name: "a database somewhere else, meant as written",
			env: map[string]string{
				"CVEFEED_DATABASE_URL": "postgres://u:p@db.internal.example:5432/corpus?sslmode=require",
				"POSTGRES_PASSWORD":    "ignored",
			},
			want: "postgres://u:p@db.internal.example:5432/corpus?sslmode=require",
		},
		{
			name: "no DSN at all, composed from the parts",
			env:  map[string]string{"POSTGRES_PASSWORD": "pw", "POSTGRES_USER": "u", "POSTGRES_DB": "d"},
			want: "postgres://u:pw@localhost:5432/d?sslmode=disable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dsnFromDotenv(tc.env); got != tc.want {
				t.Errorf("dsn = %q\nwant %q", got, tc.want)
			}
		})
	}
}

// Compose reads `PORT=5432 # local` as 5432. Reading the whole tail made the
// comment part of the port, and the DSN composed from it invalid — while a
// `#` inside a password, or inside quotes, has to survive.
func TestDotenvStripsInlineCommentsFromUnquotedValuesOnly(t *testing.T) {
	dir := t.TempDir()
	writeEnv(t, dir, `POSTGRES_PORT=5433 # published on the host
POSTGRES_PASSWORD=pa#ss
POSTGRES_USER="quoted # not a comment" # but this is
POSTGRES_DB='single # kept'
EMPTY=# nothing
`)
	env := loadDotenv(dir)
	for k, want := range map[string]string{
		"POSTGRES_PORT":     "5433",
		"POSTGRES_PASSWORD": "pa#ss",
		"POSTGRES_USER":     "quoted # not a comment",
		"POSTGRES_DB":       "single # kept",
		"EMPTY":             "",
	} {
		if got := env[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestAPasswordWithURLDelimitersSurvivesTheDSN(t *testing.T) {
	dsn := dsnFromDotenv(map[string]string{"POSTGRES_PASSWORD": "p@ss/w?rd#1"})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("the DSN built from a delimiter-laden password does not parse: %v (%q)", err, dsn)
	}
	if got, _ := u.User.Password(); got != "p@ss/w?rd#1" {
		t.Fatalf("password came back as %q from %q", got, dsn)
	}
	if u.Hostname() != "localhost" {
		t.Fatalf("host became %q from %q", u.Hostname(), dsn)
	}
}
