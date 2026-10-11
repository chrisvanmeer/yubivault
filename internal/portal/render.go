package portal

import (
	"html/template"
	"net/http"
	"strings"

	"yubivault/internal/config"
)

// keyTypeChoice is the UI representation of an administrator enabled key type.
type keyTypeChoice struct {
	Name   string
	Ykman  string
	Label  string
	Detail string
}

func keyTypeChoices(cfg *config.Config) []keyTypeChoice {
	choices := make([]keyTypeChoice, 0, len(cfg.AllowedKeyTypes()))
	for _, name := range cfg.AllowedKeyTypes() {
		algo, _ := config.YkmanAlgorithm(name)
		c := keyTypeChoice{Name: name, Ykman: algo}
		switch {
		case strings.HasPrefix(name, "rsa"):
			c.Label = "RSA " + strings.TrimPrefix(name, "rsa")
			c.Detail = "Broad compatibility, larger keys"
		case name == "eccp256":
			c.Label = "ECC P-256"
			c.Detail = "Fast, small keys, modern"
		case name == "eccp384":
			c.Label = "ECC P-384"
			c.Detail = "Higher security margin"
		default:
			c.Label = name
		}
		choices = append(choices, c)
	}
	return choices
}

func (p *Portal) renderTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.templates.ExecuteTemplate(w, name, data); err != nil {
		p.logger.Error("template rendering failed", "template", name, "error", err)
	}
}

// renderError writes an HTML error fragment suitable for HTMX targets.
func renderError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = errorFragmentTemplate.Execute(w, map[string]any{"Message": msg})
}

// errorFragmentTemplate is intentionally not part of the page template set so
// error fragments render even if a page template fails to parse.
var errorFragmentTemplate = template.Must(template.New("error-fragment").Parse(
	`<div class="animate-slide-up p-4 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-200 rounded-xl shadow-sm">
		<h3 class="font-bold text-base mb-1">Request Rejected</h3>
		<p class="text-xs leading-relaxed">{{.Message}}</p>
	</div>`))

// addQuery appends a query parameter to a URL, preserving existing values.
func addQuery(rawURL, key, value string) string {
	if value == "" {
		return rawURL
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + key + "=" + urlQueryEscape(value)
}

func urlQueryEscape(s string) string {
	return template.URLQueryEscaper(s)
}
