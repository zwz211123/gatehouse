package gh

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/term"
)

type completion struct{ value, description string }

type connectChoice struct {
	account Account
	asset   Asset
}

// Account IDs take precedence over server names, including unavailable IDs.
func (c *Core) connectChoices(l *Live, ref string) ([]connectChoice, error) {
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
		if err == nil && (byID || asset.Name == ref) {
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
	query = strings.ToLower(query)
	for _, r := range strings.ToLower(value) {
		if query != "" && r == []rune(query)[0] {
			query = string([]rune(query)[1:])
		}
	}
	return query == ""
}

func (c *Core) completions(l *Live, line string, pos int) []completion {
	if pos < 0 || pos > len(line) {
		return nil
	}
	prefix := line[:pos]
	start := strings.LastIndexAny(prefix, " \t") + 1
	query := prefix[start:]
	words := strings.Fields(prefix[:start])
	if strings.HasPrefix(prefix, "connect ") || strings.HasPrefix(prefix, "connect\t") {
		start = len("connect")
		for start < len(prefix) && (prefix[start] == ' ' || prefix[start] == '\t') {
			start++
		}
		query = prefix[start:]
		words = []string{"connect"}
	}
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
	// Completion values are redrawn verbatim by x/term, unlike menu labels.
	// Omit unsafe values instead of rewriting names and changing their meaning.
	safeChoices := choices[:0]
	for _, x := range choices {
		if terminalLabel(x.value) == x.value {
			safeChoices = append(safeChoices, x)
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
		out[i].value = prefix[:start] + out[i].value + line[pos:]
	}
	return out
}

func (c *Core) setupCompletion(l *Live, terminal *term.Terminal) {
	var candidates []completion
	last := ""
	index := -1
	terminal.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key != '\t' {
			candidates = nil
			last = ""
			return "", 0, false
		}
		if line != last || candidates == nil {
			candidates = c.completions(l, line, pos)
			index = -1
		}
		if len(candidates) == 0 {
			return line, pos, true
		}
		index = (index + 1) % len(candidates)
		if len(candidates) > 1 {
			var menu strings.Builder
			menu.WriteString("补全候选（Tab 循环选择）:\n")
			// Keep large account lists to one small page around the selection.
			pageStart := index / 8 * 8
			pageEnd := pageStart + 8
			if pageEnd > len(candidates) {
				pageEnd = len(candidates)
			}
			for i := pageStart; i < pageEnd; i++ {
				x := candidates[i]
				marker := "  "
				if i == index {
					marker = "\x1b[7m› "
				}
				fmt.Fprintf(&menu, "%s%s  — %s\x1b[0m\n", marker, terminalLabel(x.value), terminalLabel(x.description))
			}
			fmt.Fprintf(&menu, "候选 %d/%d\n", index+1, len(candidates))
			// Terminal.Write redraws the prompt and preserves wrapped-line bookkeeping.
			io.WriteString(terminal, menu.String())
		}
		last = candidates[index].value
		return last, len(last), true
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
