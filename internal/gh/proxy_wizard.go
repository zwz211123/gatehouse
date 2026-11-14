package gh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

var errWizardCancel = errors.New("cancel application")
var errWizardBack = errors.New("previous field")

type proxyWizard struct {
	core     *Core
	live     *Live
	out      io.Writer
	read     func(string) (string, error)
	spec     Spec
	advanced bool
	choices  []connectChoice
}

type proxyField struct {
	key, group, label, help string
	value                   func() string
	set                     func(string) error
}

// The JSON path deliberately keeps the existing one-line protocol and defaults.
func (c *Core) proxyCreate(l *Live, out io.Writer, read func(string) (string, error), useJSON bool) (Ticket, string, error) {
	if useJSON {
		io.WriteString(out, "请输入申请 JSON（单行，/cancel 取消）:\r\n")
		body, err := read("JSON: ")
		if err != nil {
			return Ticket{}, "", err
		}
		if strings.TrimSpace(body) == "/cancel" {
			return Ticket{}, "", nil
		}
		var s Spec
		if err := json.Unmarshal([]byte(body), &s); err != nil {
			return Ticket{}, "", fmt.Errorf("JSON 格式错误: %w", err)
		}
		t, pw, _, err := c.CreateTicket(l, s)
		return t, pw, err
	}
	w := &proxyWizard{core: c, live: l, out: out, read: read, spec: Spec{TTL: 300, Duration: 7200, Total: 1, Concurrent: 1, Sessions: 1, Channels: 1, PTY: "require", Modes: []string{"shell"}}}
	t, pw, err := w.run()
	if errors.Is(err, errWizardCancel) {
		w.print("已取消申请\n")
		return Ticket{}, "", nil
	}
	return t, pw, err
}

func (w *proxyWizard) print(format string, args ...any) {
	fmt.Fprint(w.out, strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", "\r\n"))
}

func (w *proxyWizard) input(prompt string) (string, error) {
	s, err := w.read(prompt)
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(s) {
	case "/cancel":
		return "", errWizardCancel
	case "/back":
		return "", errWizardBack
	}
	return s, nil
}

func (w *proxyWizard) run() (Ticket, string, error) {
	w.print("申请临时账号\n回车保留方括号中的值；/back 上一步；/cancel 取消。\n时间可填秒数或 5m、2h、1d。\n")
	if err := w.walk("account", false); err != nil {
		return Ticket{}, "", err
	}
	for {
		w.summary()
		w.print("\n1. 确认申请\n2. 修改目标账号\n3. 修改用途和参数\n4. 修改时间和连接限制\n5. 修改高级设置\n6. 查看 JSON\n0. 取消\n")
		s, err := w.input("选择 [0]: ")
		if errors.Is(err, errWizardBack) {
			err = w.walk("advanced", true)
			if err != nil {
				return Ticket{}, "", err
			}
			continue
		}
		if err != nil {
			return Ticket{}, "", err
		}
		switch strings.TrimSpace(s) {
		case "", "0":
			return Ticket{}, "", errWizardCancel
		case "1":
			t, pw, _, err := w.core.CreateTicket(w.live, w.spec)
			if err == nil {
				return t, pw, nil
			}
			w.print("申请未创建: %s\n已保留填写内容，可修改后重试。\n", terminalLabel(err.Error()))
		case "2", "3", "4", "5":
			key := map[string]string{"2": "account", "3": "modes", "4": "ttl", "5": "advanced"}[strings.TrimSpace(s)]
			if err := w.walk(key, true); err != nil {
				return Ticket{}, "", err
			}
		case "6":
			w.print("%s\n", terminalLabel(encode(w.spec)))
		default:
			w.print("请输入 0 到 6。\n")
		}
	}
}

// Fields are rebuilt after each answer so mode changes never leave stale prompts.
// A review edit stops at the end of its section; /back can still cross sections.
func (w *proxyWizard) walk(start string, editing bool) error {
	fields, err := w.fields()
	if err != nil {
		return err
	}
	i := 0
	for i < len(fields) && fields[i].key != start {
		i++
	}
	if i == len(fields) {
		return fmt.Errorf("申请字段不可用")
	}
	editGroup := fields[i].group
	for i < len(fields) {
		f := fields[i]
		if f.help != "" {
			w.print("\n%s\n", f.help)
		}
		current := f.value()
		prompt := f.label
		if current != "" {
			prompt += " [" + terminalLabel(current) + "]"
		}
		answer, err := w.input(prompt + ": ")
		if errors.Is(err, errWizardBack) {
			if i == 0 {
				if editing {
					return nil
				}
				w.print("已经是第一项；/cancel 取消。\n")
				continue
			}
			i--
			continue
		}
		if err != nil {
			return err
		}
		if answer == "" {
			answer = current
		}
		if err := f.set(answer); err != nil {
			w.print("%s\n", terminalLabel(err.Error()))
			continue
		}
		fields, err = w.fields()
		if err != nil {
			return err
		}
		// The current field remains present when it changes the following fields.
		i++
		if editing && f.group == editGroup && (i == len(fields) || fields[i].group != editGroup) {
			return nil
		}
	}
	return nil
}

func wizardSelection(input string, values []string) ([]string, error) {
	words := strings.Fields(strings.ReplaceAll(input, ",", " "))
	if len(words) == 0 {
		return nil, fmt.Errorf("至少选择一项。")
	}
	var selected []string
	for _, word := range words {
		n, err := strconv.Atoi(word)
		if err != nil || n < 1 || n > len(values) {
			return nil, fmt.Errorf("请输入 1 到 %d 的序号，多项用空格分隔。", len(values))
		}
		if contains(selected, values[n-1]) {
			return nil, fmt.Errorf("序号 %d 重复。", n)
		}
		selected = append(selected, values[n-1])
	}
	// Canonical ordering avoids resetting fields when the same modes are reordered.
	var out []string
	for _, v := range values {
		if contains(selected, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

func wizardSelected(selected, values []string) string {
	var out []string
	for i, v := range values {
		if contains(selected, v) {
			out = append(out, strconv.Itoa(i+1))
		}
	}
	return strings.Join(out, " ")
}

// Parse integer units without time.Duration's nanosecond overflow/rounding.
func wizardSeconds(s string, minimum int) (int, error) {
	multiplier := int64(1)
	if len(s) > 0 {
		switch s[len(s)-1] {
		case 's':
			s = s[:len(s)-1]
		case 'm':
			multiplier = 60
			s = s[:len(s)-1]
		case 'h':
			multiplier = 3600
			s = s[:len(s)-1]
		case 'd':
			multiplier = 86400
			s = s[:len(s)-1]
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("请输入整数秒数或 5m、2h、1d。")
	}
	n *= multiplier
	if n < int64(minimum) || int64(int(n)) != n {
		return 0, fmt.Errorf("时长至少为 %d 秒，且不能超出整数范围。", minimum)
	}
	return int(n), nil
}

func (w *proxyWizard) fields() ([]proxyField, error) {
	s := &w.spec
	var fields []proxyField
	text := func(key, group, label, help string, ptr *string, validate func(string) error) {
		fields = append(fields, proxyField{key, group, label, help, func() string { return *ptr }, func(v string) error {
			if v == "" {
				return fmt.Errorf("此项不能为空。")
			}
			if validate != nil {
				if err := validate(v); err != nil {
					return err
				}
			}
			*ptr = v
			return nil
		}})
	}
	number := func(key, group, label, help string, ptr *int, minimum, maximum int) {
		fields = append(fields, proxyField{key, group, label, help, func() string {
			if *ptr < minimum {
				return ""
			}
			return strconv.Itoa(*ptr)
		}, func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n < minimum || n > maximum {
				return fmt.Errorf("请输入 %d 到 %d 的整数。", minimum, maximum)
			}
			*ptr = n
			return nil
		}})
	}
	choice := func(key, group, label, help string, ptr *string, values []string) {
		fields = append(fields, proxyField{key, group, label, help, func() string {
			for i, v := range values {
				if v == *ptr {
					return strconv.Itoa(i + 1)
				}
			}
			return ""
		}, func(v string) error {
			items, err := wizardSelection(v, values)
			if err != nil {
				return err
			}
			if len(items) != 1 {
				return fmt.Errorf("请选择一项。")
			}
			*ptr = items[0]
			return nil
		}})
	}
	boolean := func(key, group, label, help string, ptr *bool) {
		fields = append(fields, proxyField{key, group, label, help, func() string {
			if *ptr {
				return "是"
			}
			return "否"
		}, func(v string) error {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "y", "yes", "是", "1":
				*ptr = true
			case "n", "no", "否", "0":
				*ptr = false
			default:
				return fmt.Errorf("请输入 是 或 否（y/n）。")
			}
			return nil
		}})
	}
	choices := w.choices
	if choices == nil {
		accounts, err := list[Account](w.core.Store, "account")
		if err != nil {
			return nil, err
		}
		for _, a := range accounts {
			if _, ok := w.core.Store.AllowedFrom(w.live.User, "proxy.create", a.ID, w.live.Source); !ok {
				continue
			}
			_, asset, _, err := w.core.ownerAccount(w.live.User, a.ID)
			if err == nil {
				choices = append(choices, connectChoice{a, asset})
			}
		}
		sort.Slice(choices, func(i, j int) bool {
			a, b := choices[i], choices[j]
			if a.asset.Name != b.asset.Name {
				return a.asset.Name < b.asset.Name
			}
			if a.account.Name != b.account.Name {
				return a.account.Name < b.account.Name
			}
			return a.account.ID < b.account.ID
		})
		if len(choices) == 0 {
			return nil, fmt.Errorf("没有可申请临时账号的目标。")
		}
		w.choices = choices
	}
	var menu strings.Builder
	menu.WriteString("目标账号")
	for i, x := range choices {
		fmt.Fprintf(&menu, "\n%d. %s / %s  %s:%d  %s", i+1, terminalLabel(x.asset.Name), terminalLabel(x.account.Name), terminalLabel(x.asset.Host), x.asset.Port, terminalLabel(x.account.ID))
	}
	fields = append(fields, proxyField{"account", "account", "账号序号", menu.String(), func() string {
		for i, x := range choices {
			if x.account.ID == s.Account {
				return strconv.Itoa(i + 1)
			}
		}
		if len(choices) == 1 {
			return "1"
		}
		return ""
	}, func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > len(choices) {
			return fmt.Errorf("请输入 1 到 %d 的序号。", len(choices))
		}
		s.Account = choices[n-1].account.ID
		var a Account
		if w.core.Store.Get("account", s.Account, &a) != nil || !a.ChrootVerified {
			s.StrictPath = false
		}
		return nil
	}})
	modes := []string{"shell", "exec", "sftp", "scp", "tcp"}
	fields = append(fields, proxyField{"modes", "purpose", "用途", "用途（多项用空格分隔）\n1. 交互终端\n2. 固定命令\n3. SFTP\n4. SCP\n5. TCP 转发", func() string { return wizardSelected(s.Modes, modes) }, func(v string) error {
		selected, err := wizardSelection(v, modes)
		if err != nil {
			return err
		}
		if slices.Equal(selected, s.Modes) {
			return nil
		}
		s.Modes = selected
		if !contains(selected, "exec") {
			s.Command = ""
		}
		if !contains(selected, "sftp") && !contains(selected, "scp") {
			s.FileRoot = ""
			s.FileOps = nil
			s.StrictPath = false
		}
		if !contains(selected, "scp") {
			s.LocalPath = ""
			s.RemotePath = ""
			s.Direction = ""
		}
		if !contains(selected, "tcp") {
			s.TCPHost = ""
			s.TCPPort = 0
			s.LocalPort = 0
			s.TCPRoute = ""
		}
		s.PTY = "forbid"
		if contains(selected, "shell") {
			s.PTY = "require"
			if len(selected) > 1 {
				s.PTY = "allow"
			}
		}
		return nil
	}})
	if contains(s.Modes, "exec") {
		text("command", "purpose", "固定命令", "逐字匹配客户端提交的命令。", &s.Command, func(v string) error {
			if len(v) > 8192 {
				return fmt.Errorf("命令不能超过 8192 字节。")
			}
			return nil
		})
	}
	files := contains(s.Modes, "sftp") || contains(s.Modes, "scp")
	if files {
		text("file_root", "purpose", "文件根目录", "", &s.FileRoot, func(v string) error {
			if !path.IsAbs(v) || path.Clean(v) != v {
				return fmt.Errorf("请输入规范的绝对路径，例如 /srv/files。")
			}
			return nil
		})
		ops := []string{"read", "write", "list", "mkdir", "remove", "rename", "metadata"}
		fields = append(fields, proxyField{"file_ops", "purpose", "文件操作", "文件操作（多项用空格分隔）\n1. 读取\n2. 写入\n3. 列出目录\n4. 创建目录\n5. 删除\n6. 重命名\n7. 修改属性", func() string { return wizardSelected(s.FileOps, ops) }, func(v string) error {
			selected, err := wizardSelection(v, ops)
			if err == nil {
				s.FileOps = selected
			}
			return err
		}})
	}
	if contains(s.Modes, "scp") {
		choice("direction", "purpose", "传输方向", "1. 上传\n2. 下载", &s.Direction, []string{"upload", "download"})
		text("local_path", "purpose", "本地路径", "", &s.LocalPath, nil)
		text("remote_path", "purpose", "远端路径", "", &s.RemotePath, func(v string) error {
			if !path.IsAbs(v) || path.Clean(v) != v || (s.FileRoot != "/" && v != s.FileRoot && !strings.HasPrefix(v, s.FileRoot+"/")) {
				return fmt.Errorf("远端路径必须是文件根目录内的绝对路径。")
			}
			return nil
		})
	}
	if contains(s.Modes, "tcp") {
		text("tcp_host", "purpose", "目标 IP", "TCP 转发固定目标 IP 和端口。", &s.TCPHost, func(v string) error {
			if net.ParseIP(v) == nil {
				return fmt.Errorf("请输入数字 IPv4 或 IPv6 地址。")
			}
			return nil
		})
		number("tcp_port", "purpose", "目标端口", "", &s.TCPPort, 1, 65535)
		number("local_port", "purpose", "本地端口", "", &s.LocalPort, 1, 65535)
		if s.TCPRoute == "" {
			s.TCPRoute = "target"
		}
		choice("tcp_route", "purpose", "连接路径", "1. 经目标服务器\n2. 由堡垒机直连（需要独立授权）", &s.TCPRoute, []string{"target", "jump"})
	}
	for _, x := range []struct {
		key, label string
		ptr        *int
		min        int
	}{{"ttl", "账号有效期", &s.TTL, 15}, {"duration", "每次连接最长时长", &s.Duration, 10}} {
		x := x
		help := ""
		if x.key == "ttl" {
			help = "账号有效期限制新连接；已建立的连接按每次连接时长计时。"
		}
		fields = append(fields, proxyField{x.key, "limits", x.label, help, func() string { return strconv.Itoa(*x.ptr) }, func(v string) error {
			n, err := wizardSeconds(strings.TrimSpace(v), x.min)
			if err != nil {
				return err
			}
			if x.key == "ttl" {
				if _, ok := secondsDeadline(now(), n); !ok {
					return fmt.Errorf("有效期超出时间戳范围。")
				}
			}
			*x.ptr = n
			return nil
		}})
	}
	number("total", "limits", "连接总次数", "每次 SSH 认证消耗一次；断线不返还。", &s.Total, 1, 100)
	number("concurrent", "limits", "同时在线连接数", "", &s.Concurrent, 1, s.Total)
	boolean("reconnect", "limits", "允许重连", "重连仍受有效期和剩余连接次数限制。", &s.Reconnect)
	boolean("advanced", "advanced", "展开高级设置", "高级设置：PTY、session、channel、流量和来源限制。", &w.advanced)
	if !w.advanced {
		return fields, nil
	}
	choice("pty", "advanced", "PTY 策略", "1. 允许\n2. 必须\n3. 禁止", &s.PTY, []string{"allow", "require", "forbid"})
	number("sessions", "advanced", "每连接 session 数", "Shell、命令和 SFTP 使用 session；此项限制每条连接可创建的 session 数。", &s.Sessions, 1, 16)
	number("channels", "advanced", "每连接 channel 数", "限制同时打开的通道，关闭后释放。TCP 转发通常需要多个通道；超限会使凭据失效。", &s.Channels, 1, 128)
	for _, x := range []struct {
		key, label string
		ptr        *int64
	}{{"max_bytes", "流量上限（字节）", &s.MaxBytes}, {"max_rate", "速率上限（字节/秒）", &s.MaxRate}} {
		x := x
		fields = append(fields, proxyField{x.key, "advanced", x.label, "0 表示不额外限制，仍受授权限制。", func() string { return strconv.FormatInt(*x.ptr, 10) }, func(v string) error {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return fmt.Errorf("请输入非负整数。")
			}
			*x.ptr = n
			return nil
		}})
	}
	fields = append(fields, proxyField{"cidrs", "advanced", "来源网段", "多个 CIDR 用空格分隔；- 清空，不额外限制来源。", func() string {
		if len(s.CIDRs) == 0 {
			return "-"
		}
		return strings.Join(s.CIDRs, " ")
	}, func(v string) error {
		if v == "-" {
			s.CIDRs = nil
			return nil
		}
		cidrs := strings.Fields(v)
		for _, cidr := range cidrs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("网段 %s 无效，请使用 CIDR，例如 192.0.2.0/24。", cidr)
			}
		}
		s.CIDRs = cidrs
		return nil
	}})
	fields = append(fields, proxyField{"env", "advanced", "环境变量", "仅支持 LANG、LC_ALL、LC_CTYPE、TZ；格式为 LANG=C TZ=UTC；- 清空。", func() string {
		var pairs []string
		for k, v := range s.Env {
			pairs = append(pairs, k+"="+v)
		}
		sort.Strings(pairs)
		if len(pairs) == 0 {
			return "-"
		}
		return strings.Join(pairs, " ")
	}, func(v string) error {
		if v == "-" {
			s.Env = nil
			return nil
		}
		env := map[string]string{}
		for _, pair := range strings.Fields(v) {
			key, value, ok := strings.Cut(pair, "=")
			if !ok || !contains([]string{"LANG", "LC_ALL", "LC_CTYPE", "TZ"}, key) || len(value) > 128 {
				return fmt.Errorf("请输入允许的 KEY=VALUE，每个值不超过 128 字节。")
			}
			if _, ok := env[key]; ok {
				return fmt.Errorf("变量 %s 重复。", key)
			}
			env[key] = value
		}
		s.Env = env
		return nil
	}})
	if files {
		fields = append(fields, proxyField{"strict_path", "advanced", "严格路径检查", "仅用于已核验 chroot 且文件根目录为 / 的目标。", func() string {
			if s.StrictPath {
				return "是"
			}
			return "否"
		}, func(v string) error {
			enabled := false
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "是", "y", "yes", "1":
				enabled = true
			case "否", "n", "no", "0":
			default:
				return fmt.Errorf("请输入 是 或 否（y/n）。")
			}
			var a Account
			if enabled && (w.core.Store.Get("account", s.Account, &a) != nil || !a.ChrootVerified || s.FileRoot != "/") {
				return fmt.Errorf("需要已核验 chroot 的目标账号，且文件根目录为 /。")
			}
			s.StrictPath = enabled
			return nil
		}})
	}
	return fields, nil
}

func (w *proxyWizard) summary() {
	s := w.spec
	_, asset, _, _ := w.core.ownerAccount(w.live.User, s.Account)
	var account Account
	w.core.Store.Get("account", s.Account, &account)
	w.print("\n申请确认\n")
	row := func(label string, value any) { w.print("%s: %s\n", label, terminalLabel(fmt.Sprint(value))) }
	row("目标", asset.Name+" / "+account.Name+" ("+s.Account+")")
	row("用途", wizardLabels(s.Modes, map[string]string{"shell": "交互终端", "exec": "固定命令", "sftp": "SFTP", "scp": "SCP", "tcp": "TCP 转发"}))
	if contains(s.Modes, "exec") {
		row("固定命令", s.Command)
	}
	if contains(s.Modes, "sftp") || contains(s.Modes, "scp") {
		row("文件根目录", s.FileRoot)
		row("文件操作", wizardLabels(s.FileOps, map[string]string{"read": "读取", "write": "写入", "list": "列出目录", "mkdir": "创建目录", "remove": "删除", "rename": "重命名", "metadata": "修改属性"}))
		row("严格路径检查", wizardYesNo(s.StrictPath))
	}
	if contains(s.Modes, "scp") {
		row("传输方向", map[string]string{"upload": "上传", "download": "下载"}[s.Direction])
		row("本地路径", s.LocalPath)
		row("远端路径", s.RemotePath)
	}
	if contains(s.Modes, "tcp") {
		row("TCP 目标", net.JoinHostPort(s.TCPHost, strconv.Itoa(s.TCPPort)))
		row("本地端口", s.LocalPort)
		row("连接路径", map[string]string{"target": "经目标服务器", "jump": "由堡垒机直连"}[s.TCPRoute])
	}
	row("账号有效期（秒）", s.TTL)
	row("每次连接时长（秒）", s.Duration)
	row("连接总次数", s.Total)
	row("同时在线连接数", s.Concurrent)
	row("允许重连", wizardYesNo(s.Reconnect))
	row("PTY", map[string]string{"allow": "允许", "require": "必须", "forbid": "禁止"}[s.PTY])
	row("每连接 session 数", s.Sessions)
	row("每连接 channel 数", s.Channels)
	if s.MaxBytes > 0 {
		row("流量上限（字节）", s.MaxBytes)
	}
	if s.MaxRate > 0 {
		row("速率上限（字节/秒）", s.MaxRate)
	}
	if len(s.CIDRs) > 0 {
		row("来源网段", strings.Join(s.CIDRs, ", "))
	}
	if len(s.Env) > 0 {
		row("环境变量", encode(s.Env))
	}
	if contains(s.Modes, "tcp") && s.Channels == 1 {
		w.print("TCP 转发当前只允许一个同时打开的通道；可在高级设置中调整。\n")
	}
}

func wizardYesNo(v bool) string {
	if v {
		return "是"
	}
	return "否"
}

func wizardLabels(values []string, labels map[string]string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, labels[v])
	}
	return strings.Join(out, "、")
}
