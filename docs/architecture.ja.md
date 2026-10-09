# YNU-WG portable gateway

WireGuard本体は改造していません。上流の `wireguard-go` を通常のライブラリとして使用します。
Goのプログラムに、対象ドメイン限定のDNS64、TCP/UDPのユーザー空間変換、Go製SIM認証、オンデマンド接続を実装しました。

```
OS / アプリ
  DNS: *.ac.jp → 実Aを専用 /96 に埋め込んだAAAA
  通信: 合成IPv6 → OSのTUN → TCP/UDP変換 → 標準WireGuard → 大学VPN
```

IPv4をIPv6末尾32ビットに埋め込むため、仮IPの割当表・同期・保持は不要です。
例: `133.34.184.6` → `fd00:596e:7500::8522:b806`。
TCPはgVisorで終端してIPv4側へ中継します。UDPはフロー単位で中継します。
これはTCP/UDP用途の変換ゲートウェイであり、全IPプロトコル対応のJool相当品ではありません。
TLSは終端しません。HTTPSのホスト名・SNI・証明書検証はアプリ側のままです。

## ビルド成果物と対応範囲

`dist/ynu-wg-{OS}-{arch}`（Windowsは `.exe`）をそのままコピーして使います。
Windows/Linux/macOS、amd64/arm64の6種類をクロスビルドします。
Goランタイムの別インストールは不要です。スマートフォン用アプリは対象外です。

| OS | パケット処理 | 認証 | 実行時の追加要件 |
|---|---|---|---|
| Windows amd64/arm64 | Wintun + Go | Go製LTE/5G認証 | 管理者権限・PowerShell・Wintun |
| Linux amd64/arm64 | TUN + Go | Go製LTE/5G認証 | root/CAP_NET_ADMIN・iproute2 |
| macOS amd64/arm64 | utun + Go | Go製LTE/5G認証 | 管理者権限 |

認証用 `loip-client.dll` と認証ヘルパーEXEの同梱・呼出しを削除しました。Wineは不要です。
WindowsのTUN実装はWintunに依存するため、署名済み `wintun.dll` はWindows版だけに残しています。
Linux/macOS版にはDLLを埋め込みません。Windowsでも完全DLL不要にするにはTUN実装の変更が必要です。

GoでTCPフレーム、Milenage、LTE認証の基本経路、5G-AKA、鍵交換、5G NAS中継、成功応答を実装しています。
2026-10-09に、提供された `.kkm` で大学サーバーの5G認証に成功し、取得した鍵で無改造WireGuardを起動して
`www.ynu.ac.jp` へのHTTPS通信（HTTP 200）を確認しました。秘密鍵・認証情報は保存もログ出力もしていません。
実通信確認はLinuxのプロセス内netstackで実施しました。OSの経路・DNS設定は変更していません。

LTEの追加NAS中継（9/10）、AUTS再同期、既存コンテキストの再接続は未移植です。
未知のメッセージやMAC不一致はエラーで終了します。現在の大学サーバーで確認した5G経路以外の完全互換性は保証しません。
暗号の公開テストベクトル、TCPの分割・結合、模擬認証、改ざん・再送拒否、セッション停止をテストしています。
Windowsの従来のDNS起動版はユーザーが接続成功を確認しています。
新しいトレイUI・自動移動・スタートアップ登録はWindows実機では未検証です。
60分を超える接続、macOSの実行、各OSの強制終了後の復旧は未検証です。


## 認証ファイルの自動探索

認証ファイルの専用フォルダやリネームは不要です。
起動時のカレントディレクトリから、最大3階層下までの有効な `.kkm` を自動で探し、そのファイルを直接使います。
移動・コピー・権限変更は行いません。拡張子の大文字小文字も区別しません。

```text
作業フォルダ/
├── ynu-wg-windows-amd64.exe
└── 配布された名前のまま.kkm
```

WindowsではEXEをダブルクリックします。Linux/macOSやCLIでは作業フォルダへ移動して実行します。
探索起点はカレントディレクトリなので、EXEの所在とは異なる場合があります。
設定やWindowsドライバーのキャッシュはプログラムが管理するため、それらを手動配置する必要はありません。

有効な認証ファイルが1種類なら自動で使用します。
同じSIM内容のコピーは1種類として扱います。Windowsのトレイ起動では自動探索で見つかったファイルのパスを記憶します。
探索で一意に見つからなければ、記憶した有効なファイルを使います。それもなければダウンロード案内とファイル選択ダイアログを表示します。
CLIでは異なるSIMが複数ある場合は停止するため、その場合だけファイルを指定します。

```powershell
.\ynu-wg-windows-amd64.exe --auth '.\任意のフォルダ\配布ファイル.kkm'
```

シンボリックリンクを辿らず、`.git`、`node_modules`、`runtime` を除外し、探索件数は最大20000です。
範囲内で見つからない場合、以前 `init --auth` で取り込んだ認証ファイルも互換性のため使用できます。


従来の `init --auth PATH`、`--portable`、`--data-dir DIR` は任意で利用できます。
`init` で取り込む場合の保管場所はWindowsの `%LOCALAPPDATA%/YNU-WG`、LinuxのXDGデータ領域、macOSのApplication Supportです。
EXE横に `data/config.json` または旧 `data/auth/sim.kkm` があれば、そのdataフォルダを設定・キャッシュ領域として自動検出します。
取込ファイルはPOSIXで0700/0600、Windowsで本人とSYSTEMのDACLに制限します。自動探索した元ファイルは変更しません。

SIMやセッション鍵をEXEに埋め込みません。
Windowsでは `runtime/` にWintunだけを展開します。旧版が生成した `loip-client.dll` と `ynu-auth-helper.exe` は起動時に削除します。
元インストーラーや解析用DLL、認証ファイルは削除しません。認証・セッション鍵はGoプロセス内だけで保持し、ログへ出しません。
`doctor` で探索結果・形式・依存関係を確認できます。大学への認証接続は開始しません。

## 起動

Windowsでは **EXEだけをダブルクリック** します。初回のUACで管理者権限を許可すると、DNS64と大学IPv4レンジの転送が有効になり、タスクトレイに常駐します。CMD・PS1・DLLの同梱ファイルは不要です。

- ダウンロードフォルダ配下から起動したEXEは `%LOCALAPPDATA%\YNU-WG\bin\ynu-wg.exe` に移して再起動し、元のEXEを削除します。ほかの場所のEXEは移動しません。
- 移動直後は元の作業フォルダを探索起点として引き継ぎ、最大3階層の `.kkm` を探索します。次回からは記憶したファイルのパスも使い、ショートカットの作業フォルダはEXEの保存先に設定します。自動で見つかった場合、ファイル選択は表示しません。
- 見つからなければ `https://vpn-stu.ynu.ac.jp:8443/` のダウンロード案内を表示します。「はい」でブラウザを開き、「いいえ」で取得済みファイルを選べます。選択したファイルのパスを記憶し、SIM自体は移動・コピーしません。
- 初回起動でスタートアップとスタートメニューに `YNU-WG` ショートカットを確認なしで登録します。次回ログイン時は登録した本人のタスクを管理者権限で実行します。スタートアップ起動時のUAC表示を避けるため、Startupショートカットから専用のタスクスケジューラタスクを呼び出します。
- トレイの右クリックからステータス、ログ、SIMダウンロードページ、ライセンス、スタートアップの有効・無効、終了を選べます。ダブルクリックでもステータスを表示します。
- ログは `%LOCALAPPDATA%\YNU-WG\ynu-wg.log`、認証ファイルのパスと起動設定は同フォルダの `desktop.json` に保存します。認証情報そのものは保存しません。設定とドライバーのキャッシュも自動生成します。
- 「終了」でセッション、追加した経路、DNS設定を片付けて終了します。起動処理が失敗した場合はエラーを表示し、トレイからログを確認できます。

配布ファイルはEXE一つです。実行時には埋め込んだ署名済みWintunをキャッシュ領域へ展開します。スタートアップ登録にはWindows標準のPowerShellとタスクスケジューラを使います。
既存のトレイ版が動いている状態で新しいEXEに更新する場合は、先にトレイから終了してください。

Linux:

```bash
./ynu-wg-linux-amd64 init --auth /path/to/your.kkm
./ynu-wg-linux-amd64 doctor
sudo ./ynu-wg-linux-amd64 --data-dir "$HOME/.local/share/ynu-wg" run --configure-dns
```

macOS:

```bash
./ynu-wg-darwin-arm64 init --auth /path/to/your.kkm
sudo ./ynu-wg-darwin-arm64 --data-dir "$HOME/Library/Application Support/YNU-WG" run --configure-dns
```

`doctor` の `auth_dependencies_present: true` は認証ファイルの確認結果であり、接続互換性の検証結果ではありません。
Windowsの引数なし起動はトレイ常駐と `run --configure-dns` です。Linux/macOSの引数なし起動は `run` と同じで、大学レンジへの実IPv4転送を行い、DNSは変更しません。
DNS64を使う場合は `run --dns64`、OSの対象ドメインDNS設定も変更する場合は `run --configure-dns` を指定します。
明示的なCLI実行では `--configure-dns` を付けたときに、対象サフィックスのOS DNS設定も変更します。
WindowsはNRPT、Linuxはresolvectlのルーティングドメイン、macOSは `/etc/resolver/ac.jp` を使います。
Ctrl+Cなど通常終了では追加した経路・DNS設定を解除します。
既存のmacOS resolverファイルは上書きしません。
強制終了や電源断後は、Windowsのコメント `ynu-wg temporary DNS64 rule` のNRPT規則、
macOSの同コメント付きresolverファイルが残る可能性があります。削除して復旧できます。

DNSだけ動かすには `dns` を使います。TUN経路は別に用意する必要があります。
DNSのTCP/UDPポートが使用中の場合は開始に失敗し、システムDNSを変更しません。

## 接続開始と終了

- 起動しただけでは大学セッションを開始しません。
- 対象DNS問い合わせ、または合成IPv6宛てのTCP SYN/データ・UDPで認証を開始します。
- 認証中は `auth_timeout_seconds`（初期値60秒）を使用し、5秒の無通信終了は適用しません。
- 認証完了後、利用通信が止まって `idle_seconds`（初期値5秒）経過したら認証TCP接続とWGを終了します。
- 送受信データで無通信タイマーを更新します。WGキープアライブ、純粋なTCP ACK/FIN/RSTは数えません。
- 新しい対象通信が来れば、認証して新規セッションを作ります。
- 認証失効・認証処理終了時はWGを閉じ、通常ネットワークへの代替接続は行いません。

5秒より長く何も送らないTCP接続も閉じます。WebSocket等を保持したければ `idle_seconds` を大きくします。
最初の認証がOS/ブラウザのDNSタイムアウトより長い場合は、初回の名前解決を再試行する必要があります。
認証先 `vpn-stu.ynu.ac.jp` の名前解決は `public_dns` へ直接送り、DNS64との循環を避けています。

## 設定

### 実IPv4をIP/CIDR指定で転送

大学レンジ `133.34.0.0/16` はコンパイル時のデフォルトとしてバイナリに組み込み済みです。
既存config.jsonで `ipv4_routes` が未指定でも、このレンジが有効になります。
DNSを変更せず、大学レンジへのTCP/UDPだけを転送する例:

```powershell
.\ynu-wg-windows-amd64.exe run --ip-only
```

単一IPも指定可能です。`--route` は複数回指定できます。

```powershell
.\ynu-wg-windows-amd64.exe run --route 203.0.113.7
```

`203.0.113.7` は書式説明用の予約アドレスです。実際の必要なIPに置き換えます。
Linux/macOSも同じオプションです。`--ip-only` ではDNSサーバーを起動せず、OSのDNSを変更せず、合成IPv6の経路も追加しません。
最初の対象IPv4通信で認証を開始し、利用通信が止まると既存の `idle_seconds` で切断します。
`--dns64` を付けるとDNS64とIPv4指定を併用できます。
DNS64の対象は `domains`、実IPv4の対象は `ipv4_routes` で、それぞれ独立した設定です。
`--route` は大学レンジへの追加指定です。config.jsonの `ipv4_routes` を明示すれば組み込み値を上書きし、空配列 `[]` なら実IPv4転送を無効にできます。

永続設定として `config.json` に追加する場合:

```json
{
  "ipv4_routes": ["133.34.0.0/16", "133.34.184.6/32"],
  "ipv4_address": "198.18.0.1"
}
```

上記は追加するフィールドの抜粋です。既存config.jsonの他のフィールドは維持します。
`ipv4_address` はTUN側のローカルIPv4で、指定レンジの外にある未使用アドレスを選びます。
設定ファイルはCIDR形式、CLIはCIDRまたは単一IPv4を受け付けます。`/0` と直接のIPv6転送は未対応です。

認証先・上流WGの接続先・通常DNSが指定レンジに含まれる場合、起動前の通常デフォルト経路へ /32 で逃がします。
外部認証コマンド独自の制御先は `bypass_ipv4` にIPv4アドレスを追加してください。
既存ルートを上書きせず、追加経路との競合やバイパス作成失敗では処理を中止します。
Linuxでは既存の通常経路を確認できた制御先 /32 はそのまま使います。
新しいトレイ版のOS経路操作とmacOS実機での経路操作は未検証です。
通常経路は起動時のデフォルト経路を基準とするため、接続中にNICやデフォルトVPNを切り替えたら再起動してください。

対象はTCP/UDPです。ICMP/pingは引き続き未対応です。
外部ホスティングやCDNのIP変更は自動追従しないため、必要なら `tools/ynu_dns.py routes --include-external-web` で候補を再取得します。
アプリが実IPv6を選んだ場合は実IPv4指定には一致しません。IPv6を含めてドメインを制御する用途はDNS64側を使います。

`config.json` の初期値を `config/example.json` に保存しています。

- `domains`: 合成対象。初期値 `ac.jp`。YNUだけなら `ynu.ac.jp` に変更。
- `campus_domains`: 大学VPN内のDNSへ問い合わせる対象。初期値 `ynu.ac.jp`。
- `public_dns`: 非対象ドメイン・他大学の実A・認証先bootstrap用DNS。
- `campus_dns`: YNUの配布設定にあった2つのDNS。認証済みWG経由で問い合わせます。
- `dns_listen`: 初期値 `127.0.0.1:53`。
- `nat64_prefix`: 初期値 `fd00:596e:7500::/96`。使用中のネットワークと重複しないものを選びます。
- `client_address`: TUN自身のIPv6アドレス。変換プレフィックスの外に置きます。
- `interface`: 初期値autoでOSごとの名前を選びます。固定名にも変更できます。
- `mtu`: OS側IPv6用は1280。上流WGのMTUは配布設定に合わせ1200。
- `auth_command`: 外部認証ヘルパーのコマンドと引数のJSON配列。シェルを通しません。
- `profile_file`: 既存の保護されたWireGuardプロファイルJSONを使用する検証・外部認証用モード。
- `allow_remote_dns`: サーバーのWG/LANアドレスでDNSを受ける場合だけtrue。既定はloopback限定。

既存プロファイルには `address`, `private_key`, `public_key`, `preshared_key`, `endpoint` を指定します。
キーはWireGuard形式の32バイトBase64、addressはIPv4、endpointは数値IP:portです。
プロファイルは認証処理自体の代わりにはなりません。期限や認証接続の維持は提供元の責任になります。

外部認証ヘルパーのプロトコル:

```
stdout: JSON Lines
  {"kind":"status","status":3}
  {"kind":"profile","profile":{...上記5項目...}}
  {"kind":"heartbeat"}
  {"kind":"error"}
stdin: stop\n またはEOFで認証切断して終了
```

4/6が認証完了、1/2は失効/切断、5は再認証中です。
秘密鍵をstdoutへ出すため、外部ヘルパーは必ずパイプ経由で起動し、stdoutを通常ログへ保存しないでください。
認証DLLホストとその `--check` は廃止しました。`doctor` でGo側の認証ファイル検証を行います。

## サーバーで利用する場合

既存の標準WireGuardをクライアント―サーバー間の下流トンネルとして使えます。
Linuxサーバーで本プログラムの `run` を実行すると、合成 /96 の経路が `ynu64` に入ります。
下流クライアントのWG `AllowedIPs` に、この /96 とサーバーのDNSアドレスを含めます。
クライアントには下流WG用のIPv6アドレスも設定します。外側のWG転送はIPv4でも構いません。
サーバーでIPv6 forwardingを有効にし、下流WGとynu64間の転送をファイアウォールで許可します。
DNSはサーバーの下流WGアドレスで待受けるよう `dns_listen` / `allow_remote_dns` を設定します。
この場合はサーバー自身のOS DNS変更は不要なので `--configure-dns` を付けません。
本プログラムがTCP/UDPを認証済み大学WGのIPv4として出すため、この経路に追加のLinux masqueradeは不要です。
下流WGの鍵・IP・SSH接続先が未提示のため、サーバーへのインストールやネットワーク変更は実施していません。

## DNSと通信の制約

対象ドメインでは既存の実AAAAを使わず、Aから強制的に合成AAAAを返します。
A・HTTPS/SVCB・ANYにはNODATAを返し、実IPv4やaddress hintsへの直接接続を避けます。
CNAMEと実AのTTLを合成応答に引き継ぎます。AがないIPv6専用サイトは利用できません。
合成応答にDNSSEC AD/RRSIGは付けません。独自DNSSEC検証を要求するクライアントは利用できません。
ブラウザ独自のDoHや固定IP指定はこのDNSを通らないため、対象ドメインの分岐を適用できません。
IPv4専用アプリ、ICMP/ping、その他のIPプロトコルは対象外です。
標準OS DNSを使うIPv6対応のWeb/TCP/UDPアプリが対象です。

## IP調査と検証

確認済みYNUレンジはJPNIC WHOISの `133.34.0.0/16`。
Webサーバーはこの範囲外の外部ホスティングも使っているため、ドメイン経由の変換を使います。
`../data/ynu-web-ips.json` は公式ページに掲載された75ホストのDNSスナップショットです。
網羅的なゾーン一覧ではなく、短いTTLのCDNアドレスは変化します。

```bash
python3 tools/ynu_dns.py match risyu.jmk.ynu.ac.jp
python3 tools/ynu_dns.py match 133.34.184.6
python3 tools/ynu_dns.py refresh
go test -race ./...
GO_BIN=/path/to/go ./build.sh
```

テスト: サフィックス境界、CNAME合成・TTL・NXDOMAIN・A/SVCB抑制、上流障害、
VPN DNSの経路選択、実IPv6パケットのTCP/UDP中継、オンデマンド認証・無通信終了・再開、
標準WireGuard同士の暗号化通信、切断時のソケット閉鎖、SIM形式とエラーの秘密情報非表示。
