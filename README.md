# YNU-VPN-Unofficial-client

横浜国立大学の学生向けVPNを利用する、非公式のGo製クライアントです。大学や公式VPN製品の開発元による提供・サポートはありません。大学から自分に発行されたSIM認証ファイル（`.kkm`）を使います。

WireGuard本体は変更せず、SIM認証、オンデマンド接続、DNS64、TCP/UDPのIPv6→IPv4中継を周辺に実装しています。認証用の独自DLLやWineは使いません。

## Windowsで使う

[Releases](https://github.com/nekorobi-0/YNU-VPN-Unofficial-client/releases)から自分のPCに合うEXEをダウンロードしてください。通常のIntel/AMD PCは `ynu-wg-windows-amd64.exe`、ARM版Windowsは `ynu-wg-windows-arm64.exe` です。公開前のビルド成果物は [Actions](https://github.com/nekorobi-0/YNU-VPN-Unofficial-client/actions) からも取得できます。

1. EXEをダブルクリックし、WindowsのUACで管理者権限を許可します。
2. ダウンロードフォルダ内から起動した場合、EXEは `%LOCALAPPDATA%\YNU-WG\bin\ynu-wg.exe` へ移動します。元のEXEは再起動後に削除します。
3. 初回は起動時の作業フォルダから深さ3まで `.kkm` を探索します。見つかればそのまま使用し、ファイル選択は表示しません。
4. 見つからなければ、[SIMダウンロードページ](https://vpn-stu.ynu.ac.jp:8443/)への案内とファイル選択を表示します。選んだファイルのパスを記憶します。SIM自体は移動・コピーしません。
5. タスクトレイに常駐します。右クリックでステータス、ログ、スタートアップの有効・無効、終了を選べます。

初回にスタートアップ・スタートメニューのショートカットを自動登録します。次回ログイン時は、登録した本人の対話セッション内で専用のタスクスケジューラタスクを起動します。

DNS64はデフォルトで有効です。対象は `ac.jp`、大学の内部DNSを使う対象は `ynu.ac.jp`。対象ドメインのAレコードから合成IPv6を返し、仮想IF経由で大学VPNのIPv4へ中継します。大学IPv4レンジ `133.34.0.0/16` へのTCP/UDP転送も有効です。

| 保存するもの | 場所 |
|---|---|
| アプリ本体（Downloadsから移動した場合） | `%LOCALAPPDATA%\YNU-WG\bin\ynu-wg.exe` |
| ログ | `%LOCALAPPDATA%\YNU-WG\ynu-wg.log` |
| 認証ファイルのパス・起動設定 | `%LOCALAPPDATA%\YNU-WG\desktop.json` |
| 接続・DNS設定 | `%LOCALAPPDATA%\YNU-WG\config.json` |
| Wintunドライバーのキャッシュ | `%LOCALAPPDATA%\YNU-WG\runtime\wintun.dll` |

配布EXEだけで起動できます。WintunはEXE内に埋め込み、実行時に展開します。SIMの秘密情報と接続時の鍵をバイナリへ埋め込むことはありません。

更新する際はトレイから終了してから、新しいEXEを起動してください。「終了」では追加した経路とDNS設定を解除します。ログや設定、ショートカットは次回利用のために残ります。

## 接続の動作と制約

- 対象DNS問い合わせまたは対象IPへの通信で認証・接続を開始します。
- 認証完了後、利用通信が止まって5秒経過するとセッションを閉じます。次の対象通信で再接続します。アプリは常駐したままです。
- HTTPSのTLSや証明書検証はブラウザ・アプリが行います。TLSを終端しません。
- TCP/UDPが対象です。ICMP/pingやIPv6専用サイトには対応しません。
- ブラウザ独自のDoHや固定IP指定はDNS64を通りません。長時間無通信のWebSocket等は切断されるため、必要なら `idle_seconds` を変更します。
- 強制終了・電源断では一時的な経路やDNS設定が残る場合があります。WindowsのNRPTではコメント `ynu-wg temporary DNS64 rule` の規則が対象です。

5G認証とWireGuard経由のHTTPS通信はLinuxのプロセス内で確認済みです。従来のWindows DNS起動版にも接続成功の報告があります。**現在のトレイUI・自動移動・スタートアップ登録と、そのXML文字コード修正はWindows実機での確認がまだ必要です。** LTEの追加NAS中継、AUTS再同期、既存コンテキスト再接続、60分超の連続利用は未検証・未対応の部分があります。

## Linux / macOS

CLIで使います。LinuxはTUN、iproute2とroot/CAP_NET_ADMIN、macOSはutunと管理者権限が必要です。

```bash
# ダウンロードしたLinux/macOSバイナリに実行権限を設定
chmod +x ynu-wg-*

# .kkmが作業フォルダ配下にあれば自動探索する
./ynu-wg-linux-amd64 doctor
sudo ./ynu-wg-linux-amd64 run --configure-dns

# macOS ARM64の例
sudo ./ynu-wg-darwin-arm64 run --configure-dns
```

ファイルを明示する場合は `--auth /path/to/file.kkm` をサブコマンドより前に指定します。引数なしの起動はLinux/macOSではIP転送のみです。WindowsでDNSを設定せずにCLI実行する場合は `run --ip-only` を指定します。

設定、認証プロトコル、DNSの挙動、サーバー上での構成、復旧時の注意点は [詳細ドキュメント](docs/architecture.ja.md) を参照してください。

## ソースからビルド

Go 1.23.1以上、Python 3、Bashが必要です。公開ビルドではGo 1.27.2を使用します。

```bash
git clone https://github.com/nekorobi-0/YNU-VPN-Unofficial-client.git
cd YNU-VPN-Unofficial-client
./build.sh
go test -race ./...
```

`build.sh` は公式のWintun 0.14.1 ZIPを取得し、固定SHA-256を検証した後に、Windows/Linux/macOS × amd64/arm64の6種類を `dist/` に作ります。Windows版はコンソールを出さないGUIサブシステムでビルドします。Goの依存関係は `go.mod` / `go.sum` で固定しています。

Windows向けに直接 `go build` / `go vet` する前も、`python3 tools/fetch_wintun.py` でビルド用ドライバーを準備してください。Wintun DLLや生成したEXEはGitには登録しません。

`data/ynu-web-ips.json` は公式ページの公開リンクから取得したDNSスナップショットです。IPアドレスは変化し、大学の全ホストを網羅するものではありません。`tools/ynu_dns.py` で照合・再取得できます。

## ライセンス

このプロジェクト独自のコード・ドキュメントは [MIT License](LICENSE) です。依存関係・署名済みWintunにはそれぞれのライセンスが適用されます。

[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) に出典とライセンスを記載しています。完全なライセンス本文・著作権表示は `licenses/` とビルド成果物に含め、Windowsではトレイから表示できます。Wintunの署名済みバイナリは [公式配布物に付属するライセンス](internal/assets/WINTUN-LICENSE.txt) に従い、変更せずPermitted API経由で使用します。

認証ファイル、SIMの秘密情報、通信ログ、元インストーラー、独自の認証DLL、解析ダンプはこのリポジトリに含めません。
