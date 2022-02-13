package ssoapp

import (
	"bytes"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/dasiyes/ivmconfig/src/pkg/config"
	"github.com/go-kit/log/level"
	"github.com/justinas/nosurf"
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

	_, err = buf.WriteTo(w)
	if err != nil {
		a.serverError(w, fmt.Errorf("while rendering template %s error raised [%v]", name, err))
		return
	}
}

// addDefaultData set the dataset for the form to be rendered
func (a *IvmSSO) addDefaultData(td *TemplateData, r *http.Request) *TemplateData {

	if td == nil {
		td = &TemplateData{}
	}

	var cid string
	cc, err := r.Cookie("c")
	if err != nil {
		cid = ""
		_ = level.Error(*a.logger).Log("method", "addDefaultData", "while getting customerID error", fmt.Sprintf("%v", err))
	} else {
		cid = cc.Value
	}

	// Compose the Google SignIn endpoint that will receive the IDToken to validate
	td.GSigninURI = composeGSuri(a.cfg)

	// generates new CSRFToken
	td.CSRFToken = nosurf.Token(r)

	td.CurrentYear = time.Now().Year()
	// td.Flash = a.session.PopString(r, "flash")
	// td.IsAuthenticated = a.isAuthenticated(r)
	td.ClientID = cid
	td.Version = a.cfg.GetVer()

	return td
}

// Compose the Google Sign In endpoint uri
func composeGSuri(cfg config.IvmCfg) string {

	apiSvcHst := cfg.GetAPIGWSvcURL()
	gslp := cfg.GetGSLoginPath()
	sch := "https"
	if strings.HasPrefix(apiSvcHst, "localhost") {
		sch = "http"
	}

	return fmt.Sprintf("%s://%s%s", sch, apiSvcHst, gslp)
}
