package gh

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zwz211123/gatehouse/internal/console"
)

type completion struct{ value, description string }

type connectChoice struct {
	account Account
	asset   Asset
}

// Account IDs take precedence over server names, including unavailable IDs.
func (c *Core) connectChoices(l *Live, ref string) ([]connectChoice, error) {
	return c.connectChoicesMatching(l, ref, false)
}

// Completion can also match name prefixes, using exactly the same account-ID
// precedence, source authorization and enabled-target checks as connection.
func (c *Core) connectChoicesMatching(l *Live, ref string, allowPrefix bool) ([]connectChoice, error) {
	accounts, err := list[Account](c.Store, "account")
	if err != nil {
		return nil, err
	}
	byID := false
	for _, a := range accounts {
		if a.ID == ref {
			accounts = []Account{a}
			byID = true
			break
		}
	}
	var choices []connectChoice
	for _, a := range accounts {
		if _, ok := c.Store.AllowedFrom(l.User, "shell.direct", a.ID, l.Source); !ok {
			continue
		}
		_, asset, _, err := c.ownerAccount(l.User, a.ID)
		if err != nil {
			continue
		}
		nameMatches := asset.Name == ref
		if allowPrefix && terminalLabel(asset.Name) == asset.Name {
			nameMatches = strings.HasPrefix(strings.ToLower(asset.Name), strings.ToLower(ref))
		}
		if byID || nameMatches {
			choices = append(choices, connectChoice{a, asset})
		}
	}
	return choices, nil
}

func (c *Core) connectTarget(l *Live, w io.Writer, read func() (string, error), args string) (string, int, error) {
	duration := 7200
	if args == "" {
		return "", 0, fmt.Errorf("用法: connect <账号ID或服务器名> [秒数]")
	}
	// Prefer a complete name (including spaces or a numeric suffix) before
	// interpreting the last word as an optional duration.
	choices, err := c.connectChoices(l, args)
	if err != nil {
		return "", 0, err
	}
	if len(choices) == 0 {
		if i := strings.LastIndexAny(args, " \t"); i >= 0 {
			choices, err = c.connectChoices(l, strings.TrimSpace(args[:i]))
			if err != nil {
				return "", 0, err
			}
			if len(choices) > 0 {
				duration, err = strconv.Atoi(args[i+1:])
				if err != nil || duration < 10 {
					return "", 0, fmt.Errorf("连接时限无效")
				}
			}
		}
	}
	if len(choices) == 0 {
		return "", 0, fmt.Errorf("没有匹配的可用账号或权限不足")
	}
	if len(choices) == 1 {
		return choices[0].account.ID, duration, nil
	}
	io.WriteString(w, "可用账号（0 返回）:\r\n")
	for i, x := range choices {
		fmt.Fprintf(w, "%d. %s / %s  %s:%d  %s\r\n", i+1, terminalLabel(x.asset.Name), terminalLabel(x.account.Name), terminalLabel(x.asset.Host), x.asset.Port, terminalLabel(x.account.ID))
	}
	for {
		io.WriteString(w, "输入账号序号: ")
		line, err := read()
		if err != nil {
			return "", 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" || line == "0" {
			return "", duration, nil
		}
		n, err := strconv.Atoi(line)
		if err == nil && n >= 1 && n <= len(choices) {
			// directMenu rechecks authorization and target availability before dialing.
			return choices[n-1].account.ID, duration, nil
		}
		io.WriteString(w, "无效选择\r\n")
	}
}

// Match prefixes first, then fish-style ordered subsequences.
func completionMatch(value, query string) bool {
	remaining := []rune(strings.ToLower(query))
	for _, r := range strings.ToLower(value) {
		if len(remaining) > 0 && r == remaining[0] {
			remaining = remaining[1:]
		}
	}
	return len(remaining) == 0
}

type completionSpan struct {
	start, end int
	query      string
	words      []string
}

// The complete current argument is replaced, even when the cursor is inside
// it. connect uses the same full-name-before-duration precedence as execution.
func (c *Core) completionSpan(l *Live, line string, pos int) (completionSpan, bool) {
	if pos < 0 || pos > len(line) || !utf8.ValidString(line) || !utf8.ValidString(line[:pos]) {
		return completionSpan{}, false
	}
	start := strings.LastIndexAny(line[:pos], " \t") + 1
	end := len(line)
	if i := strings.IndexAny(line[pos:], " \t"); i >= 0 {
		end = pos + i
	}
	words := strings.Fields(line[:start])
	commandStart := len(line) - len(strings.TrimLeft(line, " \t"))
	commandEnd := commandStart + len("connect")
	if commandEnd < len(line) && line[commandStart:commandEnd] == "connect" && (line[commandEnd] == ' ' || line[commandEnd] == '\t') && pos > commandEnd {
		start = commandEnd
		for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
			start++
		}
		if pos < start {
			return completionSpan{}, false
		}
		end = len(line)
		args := line[start:end]
		trimmedArgs := strings.TrimRight(args, " \t")
		exact, _ := c.connectChoices(l, trimmedArgs)
		if len(exact) == 0 {
			if i := strings.LastIndexAny(trimmedArgs, " \t"); i >= 0 {
				if _, err := strconv.Atoi(trimmedArgs[i+1:]); err == nil {
					// A numeric last word may still belong to an incomplete
					// name ("room 2" -> "room 20"), not a duration.
					prefixes, _ := c.connectChoicesMatching(l, trimmedArgs, true)
					if len(prefixes) == 0 {
						end = start + len(strings.TrimRight(trimmedArgs[:i], " \t"))
					}
				}
			}
		}
		if pos > end {
			return completionSpan{}, false
		}
		words = []string{"connect"}
	}
	return completionSpan{start: start, end: end, query: line[start:pos], words: words}, true
}

func (c *Core) completions(l *Live, line string, pos int) []completion {
	span, ok := c.completionSpan(l, line, pos)
	if !ok {
		return nil
	}
	query, words := span.query, span.words
	var choices []completion
	if len(words) == 0 {
		choices = []completion{{"list", "列出可用账号"}, {"search", "列出可用账号"}, {"info", "账号详情"}, {"connect", "连接目标账号"}, {"proxy", "临时账号管理"}, {"web", "Web 管理"}, {"whoami", "当前身份"}, {"clear", "清除终端输出"}, {"help", "帮助"}, {"exit", "退出"}}
	} else if len(words) == 1 && words[0] == "proxy" {
		choices = []completion{{"create", "申请临时账号"}, {"list", "查看凭据和快捷命令、清理已失效凭据"}, {"show", "重看凭据和快捷命令"}, {"revoke", "撤销凭据"}, {"delete", "删除无活动连接的失效凭据"}}
	} else if len(words) == 1 && words[0] == "web" {
		choices = []completion{{"login", "获取登录 token"}, {"revoke", "撤销 Web 会话"}, {"confirm", "确认敏感操作"}}
	} else if len(words) == 1 && contains([]string{"connect", "info"}, words[0]) {
		action := "shell.direct"
		if words[0] == "info" {
			action = "account.read"
		}
		accounts, _ := list[Account](c.Store, "account")
		servers := map[string]bool{}
		for _, a := range accounts {
			if _, ok := c.Store.AllowedFrom(l.User, action, a.ID, l.Source); ok {
				choices = append(choices, completion{a.ID, a.Name})
				if words[0] == "connect" {
					_, asset, _, err := c.ownerAccount(l.User, a.ID)
					if err == nil && asset.Name != "" && !servers[asset.Name] {
						servers[asset.Name] = true
						choices = append(choices, completion{asset.Name, "服务器"})
					}
				}
			}
		}
	} else if len(words) == 2 && words[0] == "proxy" && contains([]string{"show", "revoke", "delete"}, words[1]) {
		tickets, _ := list[Ticket](c.Store, "ticket")
		for _, t := range tickets {
			if t.Owner == l.User && (words[1] != "delete" || (ticketDeletable(t, now()) && !c.ticketConnectedForCompletion(t.ID))) {
				choices = append(choices, completion{t.ID, t.Username + " / " + t.State})
			}
		}
	}
	// Completion values are redrawn verbatim by the line editor, unlike menu labels.
	// Omit unsafe values instead of rewriting names and changing their meaning.
	safeChoices := choices[:0]
	seen := make(map[string]bool)
	for _, x := range choices {
		if terminalLabel(x.value) == x.value && !seen[x.value] {
			safeChoices = append(safeChoices, x)
			seen[x.value] = true
		}
	}
	choices = safeChoices
	var out []completion
	for _, x := range choices {
		if strings.HasPrefix(strings.ToLower(x.value), strings.ToLower(query)) {
			out = append(out, x)
		}
	}
	for _, x := range choices {
		if !strings.HasPrefix(strings.ToLower(x.value), strings.ToLower(query)) && completionMatch(x.value, query) {
			out = append(out, x)
		}
	}
	for i := range out {
		out[i].value = line[:span.start] + out[i].value + line[span.end:]
	}
	return out
}

func (c *Core) setupCompletion(l *Live, terminal *console.Terminal) {
	var candidates []completion
	original, last := "", ""
	originalPos, lastPos, index, suffixLen, start := 0, 0, -1, 0, 0
	reset := func() { candidates = nil; terminal.SetSuggestions(nil) }
	terminal.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		active := len(candidates) > 0 && line == last && pos == lastPos
		if active {
			switch key {
			case '\r', '\n':
				reset()
				return line, pos, true
			case 7: // Ctrl-G cancels the preview and restores the original input.
				reset()
				return original, originalPos, true
			case '\t', console.KeyDown, console.KeyRight:
				index = (index + 1) % len(candidates)
			case console.KeyBackTab, console.KeyUp, console.KeyLeft:
				index = (index + len(candidates) - 1) % len(candidates)
			default:
				reset()
				return "", 0, false
			}
		} else {
			reset()
			if key != '\t' {
				return "", 0, false
			}
			span, ok := c.completionSpan(l, line, pos)
			if !ok {
				return line, pos, true
			}
			candidates = c.completions(l, line, pos)
			if len(candidates) == 0 {
				return line, pos, true
			}
			original, originalPos = line, pos
			start, suffixLen = span.start, len(line)-span.end
			index = 0
		}
		last = candidates[index].value
		lastPos = len(last) - suffixLen
		_, height := terminal.Size()
		pageSize := min(8, max(1, height-2))
		pageStart := index / pageSize * pageSize
		pageEnd := min(pageStart+pageSize, len(candidates))
		rows := make([]string, 0, pageEnd-pageStart+1)
		for i := pageStart; i < pageEnd; i++ {
			marker := "  "
			if i == index {
				marker = "› "
			}
			x := candidates[i]
			label := x.value[start : len(x.value)-suffixLen]
			rows = append(rows, marker+terminalLabel(label)+"  — "+terminalLabel(x.description))
		}
		rows = append(rows, fmt.Sprintf("%d/%d · Tab/方向键选择 · Enter 接受 · Ctrl-G 取消", index+1, len(candidates)))
		terminal.SetSuggestions(rows)
		return last, lastPos, true
	}
}

func (c *Core) commandPicker(w io.Writer, read func() (string, error), t Ticket, pw string) error {
	write := func(s string) { io.WriteString(w, strings.ReplaceAll(s, "\n", "\r\n")) }
	for {
		write("快捷命令（Bash / OpenSSH / sshpass，明文包含密码）:\n0. 返回 / 不显示\n")
		for i, mode := range t.Spec.Modes {
			write(fmt.Sprintf("%d. %s\n", i+1, mode))
		}
		all := len(t.Spec.Modes) + 1
		write(fmt.Sprintf("%d. 显示全部\n输入数字选择: ", all))
		line, e := read()
		if e != nil {
			return e
		}
		line = strings.TrimSpace(line)
		if line == "" || line == "0" {
			return nil
		}
		selected := -1
		for n := 1; n <= all; n++ {
			if line == fmt.Sprint(n) {
				selected = n
				break
			}
		}
		if selected < 0 {
			write("无效选择\n")
			continue
		}
		for i, mode := range t.Spec.Modes {
			if selected == all || selected == i+1 {
				write("\n[" + mode + "]\n" + c.connectionCommand(t, pw, mode))
			}
		}
		write("注意：每条命令会单独建立连接，共享该账号的次数、并发和有效期限制。\n")
	}
}

func (c *Core) proxyListMenu(l *Live, w io.Writer, read func() (string, error)) error {
	for {
		tickets, e := list[Ticket](c.Store, "ticket")
		if e != nil {
			return e
		}
		var own []Ticket
		for _, t := range tickets {
			if t.Owner == l.User {
				own = append(own, t)
			}
			if t.Owner == l.User {
				fmt.Fprintf(w, "%d. %s %s %s %v\r\n", len(own), t.ID, t.Username, t.State, t.Spec.Modes)
			} else if _, ok := c.Store.AllowedFrom(l.User, "proxy.read", t.Spec.Account, l.Source); ok {
				fmt.Fprintf(w, "- %s %s %s %v\r\n", t.ID, t.Username, t.State, t.Spec.Modes)
			}
		}
		if len(own) == 0 {
			io.WriteString(w, "暂无自己的临时凭据\r\n")
			return nil
		}
		io.WriteString(w, "输入序号查看凭据和命令；d序号删除（如 d1）；d all 清理全部已撤销/过期/次数耗尽且无活动连接的凭据；0 返回: ")
		line, e := read()
		if e != nil {
			return e
		}
		line = strings.TrimSpace(line)
		if line == "" || line == "0" {
			return nil
		}
		if strings.Join(strings.Fields(line), " ") == "d all" {
			deleted, skipped, err := c.DeleteFinishedTickets(l)
			fmt.Fprintf(w, "已删除 %d 条，跳过 %d 条（仍可用或有活动连接）；审计日志保留\r\n", deleted, skipped)
			if err != nil {
				return err
			}
			continue
		}
		del := strings.HasPrefix(line, "d")
		value := strings.TrimPrefix(line, "d")
		index := -1
		for i := range own {
			if value == fmt.Sprint(i+1) {
				index = i
				break
			}
		}
		if index < 0 {
			io.WriteString(w, "无效选择\r\n")
			continue
		}
		if del {
			e = c.DeleteTicket(l, own[index].ID)
			if e == nil {
				io.WriteString(w, "已删除凭据记录，审计日志保留\r\n")
			}
		} else {
			var t Ticket
			var pw string
			t, pw, e = c.TicketPassword(l, own[index].ID)
			if e == nil {
				io.WriteString(w, strings.ReplaceAll(c.ConnectionSummary(t, pw), "\n", "\r\n"))
				e = c.commandPicker(w, read, t, pw)
			}
		}
		if e != nil {
			io.WriteString(w, e.Error()+"\r\n")
		}
	}
}

// Display descriptions without allowing control characters from stored names.
func terminalLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

func (c *Core) ticketConnectedForCompletion(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ticketConnected(id)
}
