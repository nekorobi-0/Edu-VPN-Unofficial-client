package desktop

import "sync"

var status = struct {
	sync.RWMutex
	text     string
	detail   string
	session  string
	authFile string
}{text: "起動準備中"}

func SetStatus(s string)  { status.Lock(); status.text = s; status.Unlock() }
func SetSession(s string) { status.Lock(); status.session = s; status.Unlock() }
func SetDetail(s string)  { status.Lock(); status.detail = s; status.Unlock() }
func Status() string {
	status.RLock()
	defer status.RUnlock()
	s := status.text
	labels := map[string]string{"idle": "待機中（通信で自動接続）", "authenticating": "認証中", "active": "接続中", "failed": "認証失敗（再試行待ち）", "stopped": "セッション停止"}
	if status.session != "" {
		s += " / " + labels[status.session]
	}
	return s
}
func Detail() string { status.RLock(); defer status.RUnlock(); return status.detail }

func SetAuthFile(s string) { status.Lock(); status.authFile = s; status.Unlock() }
func AuthFile() string     { status.RLock(); defer status.RUnlock(); return status.authFile }
