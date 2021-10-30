package ssoapp

import (
	"bytes"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-kit/kit/log/level"
)

func (a *IvmSSO) serverError(w http.ResponseWriter, err error) {
	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())
	_ = level.Error(*a.logger).Log("debug-trace", trace)

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// render is a helper function to render a specific template using the cached templates file repo
func (a *IvmSSO) Render(w http.ResponseWriter, r *http.Request, name string, td *TemplateData) {
	ts, ok := a.templateCache[name]
	if !ok {
		a.serverError(w, fmt.Errorf("the template %s does not exist", name))
		return
	}

	buf := new(bytes.Buffer)
	err := ts.Execute(buf, a.addDefaultData(td, r))
	if err != nil {
		a.serverError(w, err)
		return
	}

	buf.WriteTo(w)
}

// addDefaultData set the dataset for the form to be rendered
func (a *IvmSSO) addDefaultData(td *TemplateData, r *http.Request) *TemplateData {
	if td == nil {
		td = &TemplateData{}
	}

	//TODO [dev]: take the session ID as CSRFToken ...
	// td.CSRFToken = nosurf.Token(r)

	td.CurrentYear = time.Now().Year()
	// td.Flash = a.session.PopString(r, "flash")
	// td.IsAuthenticated = a.isAuthenticated(r)

	return td
}
