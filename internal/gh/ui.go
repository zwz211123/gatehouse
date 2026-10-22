package gh

import _ "embed"

//go:embed webui/index.html
var indexHTML string

//go:embed webui/style.css
var styleCSS string

//go:embed webui/app.js
var appJS string
