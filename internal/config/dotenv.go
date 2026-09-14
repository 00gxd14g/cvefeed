package config

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// The stack is configured by a .env file that docker compose reads. The command
// runs outside the stack and read only the process environment, so the two
// disagreed by default: `make up` brought PostgreSQL up with the file's
// password while `cvefeed scan` tried the built-in one, and the only way past
// it was to compose a DSN by hand every session.
//
// So the same file is read here. A real environment variable always wins —
// setting one is a deliberate act, and a file found by searching upwards should
// never override it.

// dotenvName is the file compose reads, and now so does the command.
const dotenvName = ".env"

// dotenvSearchDepth bounds how far up the tree the file is looked for. Enough
// to run from a subdirectory of a checkout, not so far that a stray file in a
// home directory silently configures an unrelated run.
const dotenvSearchDepth = 4

// loadDotenv reads the nearest .env at or above dir.
//
// Missing is not an error: most installations have no such file and use the
// environment, which is the more usual arrangement for a service.
func loadDotenv(dir string) map[string]string {
	for i := 0; i <= dotenvSearchDepth; i++ {
		path := filepath.Join(dir, dotenvName)
		if f, err := os.Open(path); err == nil {
			defer f.Close()
			return parseDotenv(f)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

// parseDotenv reads the shapes people actually write: comments, blank lines, a
// leading `export`, and values in either kind of quote.
func parseDotenv(r interface{ Read([]byte) (int, error) }) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" || strings.ContainsAny(key, " \t") {
			continue
		}
		out[key] = dotenvValue(strings.TrimSpace(value))
	}
	return out
}

// dotenvValue reads the right-hand side of a setting the way compose does.
//
// A quoted value runs to its closing quote and keeps everything inside it, a
// `#` included; whatever follows the closing quote is a comment. An unquoted
// value ends at the first `#` that follows whitespace — `PORT=5432 # local`
// sets 5432 — while a `#` with no space before it is part of the value, since
// passwords contain them. Reading the whole tail as the value made the
// comment part of the port and the DSN composed from it invalid.
//
// `$$` is compose's own escape, not a shell's or a .env convention. Compose
// interpolates unquoted and double-quoted values before it uses them — `$VAR`
// and `${VAR}` are substituted, and `$$` is the only way to write a literal
// dollar sign — and a single-quoted value is taken literally, `$$` included.
// The shipped .env.example says a password containing `$` has to be written
// `$$`, and the database is created with the interpolated password, so the
// reader has to undouble the same way or the DSN it composes carries a
// password the server has never seen. Only the escape is reproduced: a bare
// `$VAR` is left as written rather than substituted from the environment,
// because a value that relies on interpolation is one this file's own
// guidance rules out, and substituting it here would silently produce
// something different from what compose produced.
func dotenvValue(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			inner := value[1 : end+1]
			if value[0] == '\'' {
				return inner
			}
			return undoubleDollar(inner)
		}
	}
	for i := 1; i < len(value); i++ {
		if value[i] == '#' && (value[i-1] == ' ' || value[i-1] == '\t') {
			return undoubleDollar(strings.TrimSpace(value[:i]))
		}
	}
	if strings.HasPrefix(value, "#") {
		return ""
	}
	return undoubleDollar(value)
}

// undoubleDollar applies compose's `$$` escape.
func undoubleDollar(v string) string {
	return strings.ReplaceAll(v, "$$", "$")
}

// applyDotenv puts the file's settings into the environment, without displacing
// anything already there.
func applyDotenv(env map[string]string) {
	for k, v := range env {
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
}

// dsnFromDotenv composes the DSN the compose stack is using, aimed at this
// machine.
//
// The file holds POSTGRES_* rather than a DSN, because that is what the
// database container consumes; compose assembles the URL itself, and inside the
// network it uses the service name `postgres`. Outside it, which is where the
// command runs, the same database answers on localhost — `make up` publishes it
// there on the loopback address for exactly this reason.
func dsnFromDotenv(env map[string]string) string {
	if env == nil {
		return ""
	}
	if dsn := env["CVEFEED_DATABASE_URL"]; dsn != "" {
		// The shipped file names the compose service, which resolves inside the
		// network and nowhere else — and the command runs outside it. Any other
		// host is one the operator chose, and is left exactly as written.
		if h := dsnHost(dsn); !isComposeServiceName(h) {
			return dsn
		}
		if redirected := strings.Replace(dsn, "@"+dsnHostPort(dsn), "@localhost"+dsnPortSuffix(dsn), 1); redirected != dsn {
			return redirected
		}
	}
	pass := env["POSTGRES_PASSWORD"]
	if pass == "" {
		return "" // nothing here that the built-in default does not already say
	}
	user := firstNonEmpty(env["POSTGRES_USER"], "cvefeed")
	db := firstNonEmpty(env["POSTGRES_DB"], "cvefeed")
	port := firstNonEmpty(env["POSTGRES_PORT"], "5432")
	// The password goes through url.UserPassword rather than string
	// concatenation: a password containing '@', '/', '?' or '#' — all of them
	// ordinary in a generated secret — would otherwise be read as the end of
	// the userinfo, and the CLI would try to reach a host named after half of
	// it. Compose sidesteps the same problem by handing the container
	// PGPASSWORD separately; the CLI has only the URL.
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, pass),
		Host:     "localhost:" + port,
		Path:     "/" + db,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// isComposeServiceName reports whether a host is one of the names this
// project's compose file gives the database, which exist only on that network.
func isComposeServiceName(h string) bool {
	switch h {
	case "postgres", "db", "database":
		return true
	}
	return false
}

// dsnHost, dsnHostPort and dsnPortSuffix pick apart the authority without
// requiring the whole DSN to be a well-formed URL, since the key/value form is
// also valid and url.Parse accepts strings it cannot really represent.
func dsnHost(dsn string) string {
	hp := dsnHostPort(dsn)
	if h, _, ok := strings.Cut(hp, ":"); ok {
		return h
	}
	return hp
}

func dsnHostPort(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	if at < 0 {
		return ""
	}
	rest := dsn[at+1:]
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func dsnPortSuffix(dsn string) string {
	hp := dsnHostPort(dsn)
	if _, port, ok := strings.Cut(hp, ":"); ok {
		return ":" + port
	}
	return ""
}
