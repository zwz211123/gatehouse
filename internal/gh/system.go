package gh

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Settings struct {
	ID             string `json:"id"`
	Limits         Limits `json:"limits"`
	RetentionDays  int    `json:"retention_days"`
	MaxOutstanding int    `json:"max_outstanding"`
}

func (c *Core) settings() Settings {
	x := Settings{ID: "global", Limits: Limits{86400, 600, 100, 100, 16, 128, 0, 0}, RetentionDays: 180, MaxOutstanding: 32}
	c.Store.Get("settings", "global", &x)
	return x
}
func (c *Core) systemChange(ws *WebSession, q Change, source string) (any, error) {
	switch q.Kind {
	case "settings":
		if q.Operation != "update" || !c.webAllowed(ws, "config.update", "*") {
			return nil, ErrDenied
		}
		var x Settings
		if json.Unmarshal(q.Data, &x) != nil || x.RetentionDays < 1 || x.RetentionDays > 3650 || x.MaxOutstanding < 1 || x.MaxOutstanding > 10000 || !limitsSubset(x.Limits, Limits{86400, 600, 100, 100, 16, 128, 0, 0}) {
			return nil, errorf("invalid security settings")
		}
		x.ID = "global"
		current := c.settings()
		if q.ETag != hash(encode(current)) {
			return nil, errorf("settings changed; reload")
		}
		if e := c.changeRecord(ws.User, "settings", "global", x, false, source); e != nil {
			return nil, e
		}
		return map[string]any{"data": x, "etag": hash(encode(x))}, nil
	case "backup":
		var input struct {
			Passphrase string `json:"passphrase"`
			Archive    string `json:"archive"`
		}
		if json.Unmarshal(q.Data, &input) != nil || len(input.Passphrase) < 16 {
			return nil, errorf("archive passphrase must be at least 16 characters")
		}
		if q.Operation == "create" {
			if !c.webAllowed(ws, "backup.create", "*") {
				return nil, ErrDenied
			}
			dir := filepath.Join(c.Config.Data, "exports")
			if e := os.MkdirAll(dir, 0700); e != nil {
				return nil, e
			}
			fp := filepath.Join(dir, newID()+".ghb")
			defer os.Remove(fp)
			if e := Backup(c.Config, fp, input.Passphrase); e != nil {
				return nil, e
			}
			b, e := os.ReadFile(fp)
			if e != nil {
				return nil, e
			}
			if e = c.Audit(ws.User, "backup.export", "global", "ok", source, ""); e != nil {
				return nil, e
			}
			return map[string]any{"filename": "gatehouse-backup.ghb", "archive": base64.StdEncoding.EncodeToString(b)}, nil
		}
		if q.Operation == "restore" {
			if !c.webAllowed(ws, "backup.restore", "*") {
				return nil, ErrDenied
			}
			b, e := base64.StdEncoding.DecodeString(input.Archive)
			if e != nil || len(b) > 16<<20 {
				return nil, errorf("invalid archive; Web staging limit 16 MiB")
			}
			plain, e := unprotect(b, input.Passphrase)
			if e != nil || len(plain) > 512<<20 {
				return nil, errorf("backup authentication failed")
			}
			dir := filepath.Join(c.Config.Data, "restore-inbox")
			if e = os.MkdirAll(dir, 0700); e != nil {
				return nil, e
			}
			fp := filepath.Join(dir, newID()+".ghb")
			if e = writeExclusive(fp, b, 0600); e != nil {
				return nil, e
			}
			if e = c.Audit(ws.User, "backup.restore.stage", "global", "ok", source, ""); e != nil {
				os.Remove(fp)
				return nil, e
			}
			return map[string]string{"message": "备份已验证并暂存；停止服务后由宿主机管理员执行恢复，当前数据库未被覆盖。", "path": fp}, nil
		}
	}
	return nil, fmt.Errorf("unsupported system operation")
}
