Name:           rpm-i18n
Version:        1.0
Release:        1
Summary:        Test RPM internationalization features
Summary(de):    Testen der RPM-Internationalisierungsfunktionen
Summary(ja):    RPM国際化機能のテスト
Summary(fr):    Test des fonctionnalités d'internationalisation RPM
Summary(zh_CN): 测试RPM国际化功能
License:        MIT
BuildArch:      noarch

%description
A package for exercising RPM internationalization (i18n) features
including localized metadata and language-tagged files.

%description -l de
Ein Paket zum Testen der RPM-Internationalisierungsfunktionen,
einschließlich lokalisierter Metadaten und sprachmarkierter Dateien.

%description -l ja
ローカライズされたメタデータと言語タグ付きファイルを含む、
RPM国際化（i18n）機能をテストするためのパッケージ。

%description -l fr
Un paquet pour tester les fonctionnalités d'internationalisation (i18n)
de RPM, y compris les métadonnées localisées et les fichiers balisés par langue.

%description -l zh_CN
一个用于测试RPM国际化（i18n）功能的软件包，
包括本地化元数据和语言标记文件。

%install
mkdir -p %{buildroot}/usr/share/%{name}/locale/{en,de,ja,fr,zh_CN}
echo "Hello"       > %{buildroot}/usr/share/%{name}/locale/en/messages.txt
echo "Hallo"       > %{buildroot}/usr/share/%{name}/locale/de/messages.txt
echo "こんにちは"  > %{buildroot}/usr/share/%{name}/locale/ja/messages.txt
echo "Bonjour"     > %{buildroot}/usr/share/%{name}/locale/fr/messages.txt
echo "你好"        > %{buildroot}/usr/share/%{name}/locale/zh_CN/messages.txt
echo "common data" > %{buildroot}/usr/share/%{name}/common.txt

%files
/usr/share/%{name}/common.txt
%lang(en) /usr/share/%{name}/locale/en/messages.txt
%lang(de) /usr/share/%{name}/locale/de/messages.txt
%lang(ja) /usr/share/%{name}/locale/ja/messages.txt
%lang(fr) /usr/share/%{name}/locale/fr/messages.txt
%lang(zh_CN) /usr/share/%{name}/locale/zh_CN/messages.txt

%changelog
* Sat Mar 21 2026 Test User <test@example.com> - 1.0-1
- Initial package with i18n support
