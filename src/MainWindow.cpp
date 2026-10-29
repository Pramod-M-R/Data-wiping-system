#include "MainWindow.h"
#include "DeviceManager.h"
#include "FileScanner.h"
#include "WipeEngine.h"
#include "ImageBackgroundWidget.h"
#include <QAbstractItemModel>
#include <QApplication>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QStackedWidget>
#include <QString>
#include <QStringList>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidget>
#include <map>
#include <cmath>
#include "RandomForest.h"
#include <functional>
#include <cstdint>
#include <cstring>
#include <windows.h>

namespace {
const QString cardStyle = QStringLiteral("QFrame#contentCard { background-color:rgba(7,10,20,238); border:1px solid rgba(109,145,181,72); border-radius:14px; }");
QLabel* heading(const QString& text, QWidget* parent=nullptr) { auto* l=new QLabel(text,parent); l->setStyleSheet(QStringLiteral("color:#f4f8ff; font-size:18px; font-weight:700;")); return l; }
QLabel* bodyText(const QString& text, QWidget* parent=nullptr) { auto* l=new QLabel(text,parent); l->setWordWrap(true); l->setStyleSheet(QStringLiteral("color:#b5c5d9; font-size:13px;")); return l; }
QFrame* makeCard(QWidget* parent=nullptr) { auto* f=new QFrame(parent); f->setObjectName(QStringLiteral("contentCard")); f->setStyleSheet(cardStyle); return f; }
QWidget* scrollPage(QWidget* content) { auto* s=new QScrollArea; s->setWidgetResizable(true); s->setFrameShape(QFrame::NoFrame); s->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded); s->setStyleSheet(QStringLiteral("QScrollArea { background:transparent; } QScrollArea > QWidget > QWidget { background:transparent; } QScrollBar:vertical { background:rgba(4,16,42,130); width:9px; margin:2px; } QScrollBar::handle:vertical { background:#477b9e; border-radius:4px; min-height:24px; }")); s->setWidget(content); return s; }
void stylePrimaryButton(QPushButton* b) { b->setCursor(Qt::PointingHandCursor); b->setMinimumHeight(40); b->setStyleSheet(QStringLiteral("QPushButton { color:white; background:#1677c8; border:0; border-radius:8px; padding:8px 14px; font-weight:700; } QPushButton:hover { background:#2395dc; } QPushButton:disabled { background:#465b70; color:#aab8c5; } QPushButton:focus { border:2px solid #72dafa; }")); }
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("DataGuard — Secure. Recover. Verify."));
    setMinimumSize(960,640); resize(1240,820);
    auto* background=new ImageBackgroundWidget(this);
    auto* shell=new QHBoxLayout(background); shell->setContentsMargins(18,18,18,18); shell->setSpacing(14);
    auto* sidebar=new QFrame(background); sidebar->setObjectName(QStringLiteral("sidebar")); sidebar->setFixedWidth(218);
    sidebar->setStyleSheet(QStringLiteral("QFrame#sidebar { background-color:rgba(7,9,18,244); border:1px solid rgba(109,145,181,60); border-radius:16px; }"));
    auto* side=new QVBoxLayout(sidebar); side->setContentsMargins(14,18,14,16); side->setSpacing(8);
    auto* brand=new QLabel(QStringLiteral("◈  DataGuard"),sidebar); brand->setStyleSheet(QStringLiteral("color:#f6f9ff; font-size:19px; font-weight:800; padding:4px 6px;"));
    auto* tag=new QLabel(QStringLiteral("SECURE. RECOVER. VERIFY."),sidebar); tag->setStyleSheet(QStringLiteral("color:#7795b3; font-size:9px; letter-spacing:1px; padding:0 8px 14px 8px;")); side->addWidget(brand); side->addWidget(tag);
    const QStringList names={QStringLiteral("Dashboard"),QStringLiteral("Devices"),QStringLiteral("Scan Results"),QStringLiteral("Operations"),QStringLiteral("Activity Log"),QStringLiteral("Certificates"),QStringLiteral("Assistant"),QStringLiteral("Settings")};
    const QStringList icons={QStringLiteral("⌂"),QStringLiteral("▣"),QStringLiteral("⌕"),QStringLiteral("↻"),QStringLiteral("◷"),QStringLiteral("▤"),QStringLiteral("✦"),QStringLiteral("⚙")};
    for(int i=0;i<names.size();++i) {
        auto* b=new QToolButton(sidebar); b->setText(icons[i]+QStringLiteral("   ")+names[i]); b->setToolButtonStyle(Qt::ToolButtonTextOnly); b->setCheckable(true); b->setAutoExclusive(true); b->setMinimumHeight(42); b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(QStringLiteral("QToolButton { color:#b5c5d9; background:transparent; border:1px solid transparent; border-radius:9px; text-align:left; padding:0 11px; font-size:13px; } QToolButton:hover { color:white; background:rgba(43,86,124,125); } QToolButton:checked { color:#eafaff; background:rgba(21,119,171,145); border-left:3px solid #65d9f7; font-weight:700; } QToolButton:focus { border:1px solid #65d9f7; }"));
        side->addWidget(b); m_navigationButtons.push_back(b); connect(b,&QToolButton::clicked,this,[this,i,names](){navigateTo(i,names[i]);});
    }
    side->addStretch(); shell->addWidget(sidebar);
    auto* right=new QWidget(background); right->setStyleSheet(QStringLiteral("background:transparent;")); auto* rightLayout=new QVBoxLayout(right); rightLayout->setContentsMargins(0,0,0,0); rightLayout->setSpacing(12);
    auto* header=new QFrame(right); header->setObjectName(QStringLiteral("header")); header->setStyleSheet(QStringLiteral("QFrame#header { background-color:rgba(7,9,18,240); border:1px solid rgba(109,145,181,60); border-radius:14px; }"));
    auto* hl=new QHBoxLayout(header); hl->setContentsMargins(20,10,16,10); m_pageTitle=new QLabel(QStringLiteral("Dashboard"),header); m_pageTitle->setStyleSheet(QStringLiteral("color:#f4f8ff; font-size:20px; font-weight:700;")); hl->addWidget(m_pageTitle); hl->addStretch();
    m_accountLabel=new QLabel(QStringLiteral("Signed out"),header); m_accountLabel->setStyleSheet(QStringLiteral("color:#c6d5e8; font-size:12px; padding:0 8px;")); hl->addWidget(m_accountLabel);
    auto* logout=new QPushButton(QStringLiteral("Sign Out"),header); logout->setCursor(Qt::PointingHandCursor); logout->setStyleSheet(QStringLiteral("QPushButton { color:#eaf5ff; background:rgba(44,73,105,170); border:1px solid rgba(148,186,216,90); border-radius:8px; padding:8px 13px; } QPushButton:hover { background:rgba(64,101,139,210); }")); connect(logout,&QPushButton::clicked,this,&MainWindow::signOut); hl->addWidget(logout); rightLayout->addWidget(header);
    m_pages=new QStackedWidget(right); m_pages->setStyleSheet(QStringLiteral("QStackedWidget { background:transparent; }"));
    m_pages->addWidget(buildDashboardPage()); m_pages->addWidget(buildDevicesPage()); m_pages->addWidget(buildScanResultsPage()); m_pages->addWidget(buildOperationsPage());
    m_pages->addWidget(buildPlaceholderPage(QStringLiteral("Activity Log"),QStringLiteral("Activity records are not yet presented in this view."),QStringLiteral("◷")));
    m_pages->addWidget(buildPlaceholderPage(QStringLiteral("Certificates"),QStringLiteral("Certificate generation code is preserved; certificate browsing is not connected to this page yet."),QStringLiteral("▤")));
    m_pages->addWidget(buildPlaceholderPage(QStringLiteral("DataGuard Assistant"),QStringLiteral("The assistant is not connected to an active backend in this build."),QStringLiteral("✦")));
    m_pages->addWidget(buildSettingsPage()); rightLayout->addWidget(m_pages,1); shell->addWidget(right,1); setCentralWidget(background);

    connect(refreshButton,&QPushButton::clicked,this,&MainWindow::onRefreshClicked);
    connect(scanButton,&QPushButton::clicked,this,&MainWindow::onScanClicked);
    connect(wipeButton,&QPushButton::clicked,this,&MainWindow::onWipeClicked);
    connect(showDeletedCheck,&QCheckBox::toggled,this,&MainWindow::onToggleDeleted);
    connect(fileTree,&QTreeWidget::itemChanged,this,[this](QTreeWidgetItem* item,int col){if(col==0) onFileChecked(item,col);});
    connect(driveList,&QListWidget::itemSelectionChanged,this,[this](){const bool selected=driveList->currentRow()>=0; wipeButton->setEnabled(selected); scanButton->setEnabled(selected);});
    auto refreshSummary=[this](){if(m_dashboardDeviceCount)m_dashboardDeviceCount->setText(QString::number(driveList->count())); if(m_dashboardEntryCount)m_dashboardEntryCount->setText(QString::number(fileTree->topLevelItemCount())); if(m_dashboardWipeMethod)m_dashboardWipeMethod->setText(wipeMethodCombo->currentText());};
    connect(driveList->model(),&QAbstractItemModel::modelReset,this,refreshSummary);
    connect(driveList->model(),&QAbstractItemModel::rowsInserted,this,[refreshSummary](const QModelIndex&,int,int){refreshSummary();});
    connect(driveList->model(),&QAbstractItemModel::rowsRemoved,this,[refreshSummary](const QModelIndex&,int,int){refreshSummary();});
    connect(scanButton,&QPushButton::clicked,this,refreshSummary);
    connect(wipeMethodCombo,&QComboBox::currentTextChanged,this,[this](const QString& s){if(m_dashboardWipeMethod)m_dashboardWipeMethod->setText(s);});
    connect(m_dashboardRefreshButton,&QPushButton::clicked,this,[this](){m_navigationButtons[1]->setChecked(true);navigateTo(1,QStringLiteral("Devices"));refreshButton->click();});
    connect(m_dashboardOpenScanButton,&QPushButton::clicked,this,[this](){m_navigationButtons[2]->setChecked(true);navigateTo(2,QStringLiteral("Scan Results"));});
    connect(m_dashboardOpenOperationsButton,&QPushButton::clicked,this,[this](){m_navigationButtons[3]->setChecked(true);navigateTo(3,QStringLiteral("Operations"));});
    refreshSummary(); m_navigationButtons[0]->setChecked(true); setSignedInUser(QString());
}
void MainWindow::setSignedInUser(const QString& username)
{
    m_signedInUser=username.trimmed();
    if(m_accountLabel)m_accountLabel->setText(m_signedInUser.isEmpty()?QStringLiteral("Signed out"):m_signedInUser);
    if(m_settingsUsername)m_settingsUsername->setText(m_signedInUser.isEmpty()?QStringLiteral("No active session"):m_signedInUser);
}
void MainWindow::navigateTo(int index,const QString& title)
{
    if(!m_pages||index<0||index>=m_pages->count())return;
    m_pages->setCurrentIndex(index); if(m_pageTitle)m_pageTitle->setText(title);
}
void MainWindow::signOut()
{
    setSignedInUser(QString()); if(!m_navigationButtons.isEmpty())m_navigationButtons[0]->setChecked(true);
    navigateTo(0,QStringLiteral("Dashboard")); emit signOutRequested();
}
QWidget* MainWindow::buildDashboardPage()
{
    auto* content=new QWidget; auto* layout=new QVBoxLayout(content); layout->setContentsMargins(4,4,8,8); layout->setSpacing(14);
    auto* hero=makeCard(content); auto* hl=new QHBoxLayout(hero); hl->setContentsMargins(24,22,24,22); hl->setSpacing(20);
    auto* glyph=new QLabel(QStringLiteral("◈"),hero); glyph->setAlignment(Qt::AlignCenter); glyph->setFixedSize(76,76); glyph->setStyleSheet(QStringLiteral("color:#70dcf7; background:rgba(27,94,135,100); border:1px solid rgba(112,220,247,95); border-radius:20px; font-size:36px;")); hl->addWidget(glyph);
    auto* text=new QVBoxLayout; text->setSpacing(8); auto* title=heading(QStringLiteral("Secure. Recover. Verify."),hero); title->setStyleSheet(QStringLiteral("color:#f4f8ff; font-size:24px; font-weight:700;")); text->addWidget(title);
    text->addWidget(bodyText(QStringLiteral("Access the existing device scanner, file selection, secure-wipe methods and ML evaluation from one dashboard."),hero)); hl->addLayout(text,1); layout->addWidget(hero);
    auto* metrics=new QGridLayout; metrics->setSpacing(12);
    auto addMetric=[content,metrics](int col,const QString& label,QLabel*& value){auto* card=makeCard(content);auto* box=new QVBoxLayout(card);box->setContentsMargins(18,16,18,16);box->setSpacing(8);box->addWidget(bodyText(label,card));value=new QLabel(QStringLiteral("0"),card);value->setStyleSheet(QStringLiteral("color:#eff9ff; font-size:27px; font-weight:800;"));box->addWidget(value);metrics->addWidget(card,0,col);};
    addMetric(0,QStringLiteral("Detected removable devices"),m_dashboardDeviceCount); addMetric(1,QStringLiteral("Top-level scan entries"),m_dashboardEntryCount);
    auto* method=makeCard(content); auto* ml=new QVBoxLayout(method); ml->setContentsMargins(18,16,18,16); ml->setSpacing(8); ml->addWidget(bodyText(QStringLiteral("Selected wipe method"),method)); m_dashboardWipeMethod=new QLabel(QStringLiteral("Single Pass - Zeros"),method); m_dashboardWipeMethod->setWordWrap(true); m_dashboardWipeMethod->setStyleSheet(QStringLiteral("color:#eff9ff; font-size:18px; font-weight:800;")); ml->addWidget(m_dashboardWipeMethod); metrics->addWidget(method,0,2); layout->addLayout(metrics);
    auto* actions=makeCard(content); auto* al=new QVBoxLayout(actions); al->setContentsMargins(20,16,20,18); al->setSpacing(10); al->addWidget(heading(QStringLiteral("Quick actions"),actions)); al->addWidget(bodyText(QStringLiteral("These actions open the existing backend controls; they do not start a separate scanner or wiper."),actions));
    auto* row=new QHBoxLayout; m_dashboardRefreshButton=new QPushButton(QStringLiteral("Detect Devices"),actions); m_dashboardOpenScanButton=new QPushButton(QStringLiteral("Open Scan Results"),actions); m_dashboardOpenOperationsButton=new QPushButton(QStringLiteral("Open Operations"),actions);
    stylePrimaryButton(m_dashboardRefreshButton);stylePrimaryButton(m_dashboardOpenScanButton);stylePrimaryButton(m_dashboardOpenOperationsButton);row->addWidget(m_dashboardRefreshButton);row->addWidget(m_dashboardOpenScanButton);row->addWidget(m_dashboardOpenOperationsButton);al->addLayout(row);layout->addWidget(actions);layout->addStretch();return scrollPage(content);
}
QWidget* MainWindow::buildDevicesPage()
{
    auto* c=new QWidget;auto* l=new QVBoxLayout(c);l->setContentsMargins(4,4,8,8);l->setSpacing(12);auto* card=makeCard(c);auto* b=new QVBoxLayout(card);b->setContentsMargins(18,16,18,16);b->setSpacing(10);
    b->addWidget(heading(QStringLiteral("Connected removable devices"),card));statusLabel=bodyText(QStringLiteral("Ready — detect devices to begin."),card);b->addWidget(statusLabel);refreshButton=new QPushButton(QStringLiteral("Detect USB Devices"),card);stylePrimaryButton(refreshButton);b->addWidget(refreshButton,0,Qt::AlignLeft);
    driveList=new QListWidget(card);driveList->setMinimumHeight(230);driveList->setStyleSheet(QStringLiteral("QListWidget { color:#eef6ff; background:rgba(2,11,29,150); border:1px solid rgba(122,177,211,65); border-radius:9px; padding:4px; outline:0; } QListWidget::item { padding:12px 10px; border-bottom:1px solid rgba(122,177,211,45); } QListWidget::item:selected { background:rgba(21,119,171,150); border-left:3px solid #65d9f7; } QListWidget::item:hover { background:rgba(43,86,124,100); }"));b->addWidget(driveList,1);
    b->addWidget(bodyText(QStringLiteral("Select a device to enable scanning and wiping. The original device enumeration is used."),card));l->addWidget(card,1);return scrollPage(c);
}
QWidget* MainWindow::buildScanResultsPage()
{
    auto* c=new QWidget;auto* l=new QVBoxLayout(c);l->setContentsMargins(4,4,8,8);l->setSpacing(12);auto* controls=makeCard(c);auto* cl=new QVBoxLayout(controls);cl->setContentsMargins(18,16,18,16);cl->setSpacing(10);cl->addWidget(heading(QStringLiteral("File scanner"),controls));auto* row=new QHBoxLayout;
    scanButton=new QPushButton(QStringLiteral("Scan Selected Drive"),controls);stylePrimaryButton(scanButton);scanButton->setEnabled(false);row->addWidget(scanButton);showDeletedCheck=new QCheckBox(QStringLiteral("Show Deleted Files"),controls);showDeletedCheck->setChecked(true);showDeletedCheck->setStyleSheet(QStringLiteral("color:#d6e5f5; spacing:8px;"));row->addWidget(showDeletedCheck);row->addStretch();cl->addLayout(row);scanStatusLabel=bodyText(QStringLiteral("Select a drive and click Scan."),controls);cl->addWidget(scanStatusLabel);l->addWidget(controls);
    auto* results=makeCard(c);auto* rl=new QVBoxLayout(results);rl->setContentsMargins(14,12,14,14);rl->setSpacing(8);rl->addWidget(heading(QStringLiteral("Scan results"),results));fileTree=new QTreeWidget(results);fileTree->setHeaderLabels({QStringLiteral("Name"),QStringLiteral("Size"),QStringLiteral("Status"),QStringLiteral("Modified")});fileTree->header()->setSectionResizeMode(0,QHeaderView::Stretch);fileTree->setMinimumHeight(250);
    fileTree->setStyleSheet(QStringLiteral("QTreeWidget { color:#e5effb; background:rgba(2,11,29,150); alternate-background-color:rgba(9,24,43,180); border:1px solid rgba(122,177,211,65); border-radius:9px; font-size:12px; } QTreeWidget::item { padding:5px; } QTreeWidget::item:selected { background:rgba(21,119,171,150); } QHeaderView::section { color:#cfe2f4; background:rgba(20,40,63,240); border:0; border-bottom:1px solid rgba(122,177,211,65); padding:8px; font-weight:700; }"));rl->addWidget(fileTree,1);l->addWidget(results,1);return scrollPage(c);
}
QWidget* MainWindow::buildOperationsPage()
{
    auto* c=new QWidget;auto* l=new QVBoxLayout(c);l->setContentsMargins(4,4,8,8);l->setSpacing(14);auto* intro=makeCard(c);auto* il=new QVBoxLayout(intro);il->setContentsMargins(18,16,18,16);il->setSpacing(8);il->addWidget(heading(QStringLiteral("Secure wipe operations"),intro));il->addWidget(bodyText(QStringLiteral("The existing wipe engine, verification, fingerprints, similarity score, recoverability score and risk recommendation remain in use. Wiping is destructive; confirm the target carefully."),intro));l->addWidget(intro);
    auto* card=makeCard(c);auto* wl=new QVBoxLayout(card);wl->setContentsMargins(20,18,20,18);wl->setSpacing(12);auto* mr=new QHBoxLayout;mr->addWidget(bodyText(QStringLiteral("Wipe method"),card));mr->addStretch();wipeMethodCombo=new QComboBox(card);wipeMethodCombo->addItem(QStringLiteral("Single Pass - Zeros"),0);wipeMethodCombo->addItem(QStringLiteral("DoD 3-Pass (Recommended)"),1);wipeMethodCombo->addItem(QStringLiteral("DoD 7-Pass (Maximum)"),2);wipeMethodCombo->setMinimumWidth(260);wipeMethodCombo->setStyleSheet(QStringLiteral("QComboBox { color:#edf6ff; background:rgba(2,11,29,190); border:1px solid rgba(122,177,211,80); border-radius:7px; padding:8px; } QComboBox QAbstractItemView { color:#edf6ff; background:#101f34; selection-background-color:#1677c8; }"));mr->addWidget(wipeMethodCombo);wl->addLayout(mr);
    wipeButton=new QPushButton(QStringLiteral("START WIPE"),card);stylePrimaryButton(wipeButton);wipeButton->setMinimumHeight(48);wipeButton->setStyleSheet(QStringLiteral("QPushButton { color:white; background:#b83245; border:0; border-radius:9px; padding:12px 18px; font-size:14px; font-weight:800; } QPushButton:hover { background:#d64255; } QPushButton:disabled { background:#465b70; color:#aab8c5; }"));wipeButton->setEnabled(false);wl->addWidget(wipeButton);
    progressBar=new QProgressBar(card);progressBar->setRange(0,100);progressBar->setValue(0);progressBar->setStyleSheet(QStringLiteral("QProgressBar { color:#eef6ff; background:rgba(2,11,29,180); border:1px solid rgba(122,177,211,65); border-radius:7px; text-align:center; min-height:18px; } QProgressBar::chunk { background:#20a3c5; border-radius:6px; }"));wl->addWidget(progressBar);progressLabel=bodyText(QStringLiteral("Select a device and press START WIPE."),card);progressLabel->setAlignment(Qt::AlignCenter);wl->addWidget(progressLabel);l->addWidget(card);l->addStretch();return scrollPage(c);
}
QWidget* MainWindow::buildPlaceholderPage(const QString& titleText,const QString& message,const QString& glyph)
{
    auto* p=new QWidget;auto* l=new QVBoxLayout(p);l->setContentsMargins(4,8,8,12);l->addStretch();auto* c=makeCard(p);c->setMaximumWidth(680);auto* b=new QVBoxLayout(c);b->setContentsMargins(32,32,32,32);b->setSpacing(14);auto* icon=new QLabel(glyph,c);icon->setAlignment(Qt::AlignCenter);icon->setStyleSheet(QStringLiteral("color:#70dcf7; font-size:32px;"));b->addWidget(icon);auto* h=heading(titleText,c);h->setAlignment(Qt::AlignCenter);h->setStyleSheet(QStringLiteral("color:#f4f8ff; font-size:24px; font-weight:700;"));b->addWidget(h);auto* m=bodyText(message,c);m->setAlignment(Qt::AlignCenter);b->addWidget(m);l->addWidget(c,0,Qt::AlignHCenter);l->addStretch();return p;
}
QWidget* MainWindow::buildSettingsPage()
{
    auto* p=new QWidget;auto* l=new QVBoxLayout(p);l->setContentsMargins(4,8,8,12);l->setSpacing(14);auto* account=makeCard(p);auto* al=new QVBoxLayout(account);al->setContentsMargins(20,18,20,18);al->setSpacing(12);al->addWidget(heading(QStringLiteral("Account"),account));auto* nr=new QHBoxLayout;nr->addWidget(bodyText(QStringLiteral("Signed-in username"),account));nr->addStretch();m_settingsUsername=new QLabel(QStringLiteral("No active session"),account);m_settingsUsername->setStyleSheet(QStringLiteral("color:#edf6ff; font-weight:700;"));nr->addWidget(m_settingsUsername);al->addLayout(nr);auto* dr=new QHBoxLayout;dr->addWidget(bodyText(QStringLiteral("Persistence"),account));dr->addStretch();auto* mode=new QLabel(QStringLiteral("Local SQLite"),account);mode->setStyleSheet(QStringLiteral("color:#edf6ff; font-weight:700;"));dr->addWidget(mode);al->addLayout(dr);l->addWidget(account);auto* about=makeCard(p);auto* ab=new QVBoxLayout(about);ab->setContentsMargins(20,18,20,18);ab->setSpacing(8);ab->addWidget(heading(QStringLiteral("Application"),about));ab->addWidget(bodyText(QStringLiteral("DataGuard desktop application\nSecure. Recover. Verify."),about));l->addWidget(about);auto* logout=new QPushButton(QStringLiteral("Sign Out"),p);stylePrimaryButton(logout);logout->setMaximumWidth(170);connect(logout,&QPushButton::clicked,this,&MainWindow::signOut);l->addWidget(logout,0,Qt::AlignLeft);l->addStretch();return p;
}
void MainWindow::onRefreshClicked() {
    driveList->clear();
    fileTree->clear();
    wipeButton->setEnabled(false);
    scanButton->setEnabled(false);
    statusLabel->setText("Scanning ports...");

    DeviceManager dm;
    auto drives = dm.listRemovableDrives();

    if (drives.empty()) {
        driveList->addItem("No removable drives found.");
        statusLabel->setText("No devices detected.");
        return;
    }

    for (auto &d : drives) {
        QString entry = QString("[%1:\\]  %2  |  %3 MB  |  %4")
            .arg(d.letter)
            .arg(QString::fromStdString(d.model))
            .arg(d.sizeBytes / (1024 * 1024))
            .arg(QString::fromStdString(d.path));
        driveList->addItem(entry);
    }

    statusLabel->setText(
        QString("%1 device(s) detected. Select one.")
            .arg(drives.size()));
}

// ── Scan files ─────────────────────────────────────────────

void MainWindow::onScanClicked() {
    int row = driveList->currentRow();
    if (row < 0) return;

    DeviceManager dm;
    auto drives = dm.listRemovableDrives();
    if (row >= (int)drives.size()) return;

    auto &drive = drives[row];
    fileTree->clear();
    scanStatusLabel->setText("Scanning... please wait.");
    QApplication::processEvents();

    std::string root = std::string(1, drive.letter) + ":";
    
    // Store current drive info for wipe operation
    currentDriveLetter = drive.letter;
    currentDrivePath = drive.path;

    // ── Root drive node ────────────────────────────────────
    auto *rootItem = new QTreeWidgetItem(fileTree);
    rootItem->setText(0, QString::fromStdString(root + "\\"));
    rootItem->setText(2, "Drive Root");
    rootItem->setForeground(0, QColor("#00cfff"));
    rootItem->setExpanded(true);

    // ── Recursive tree builder ─────────────────────────────
    std::function<void(const std::string&, QTreeWidgetItem*)> buildTree;
    buildTree = [&](const std::string& path, QTreeWidgetItem* parent) {
        std::string searchPath = path + "\\*";
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            std::string name = fd.cFileName;
            if (name == "." || name == "..") continue;

            bool isDir = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
            std::string fullPath = path + "\\" + name;

            auto *item = new QTreeWidgetItem(parent);
            item->setText(0, QString::fromStdString(name));

            if (isDir) {
                item->setText(1, "—");
                item->setText(2, "Folder");
                item->setText(3, "—");
                item->setForeground(0, QColor("#f0c040"));
                item->setExpanded(false);
                buildTree(fullPath, item);
            } else {
                ULARGE_INTEGER size;
                size.LowPart  = fd.nFileSizeLow;
                size.HighPart = fd.nFileSizeHigh;
                item->setText(1, QString("%1 KB")
                                  .arg(size.QuadPart / 1024));
                item->setText(2, "Existing");
                item->setText(3, "—");
                item->setCheckState(0, Qt::Unchecked);
            }

        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    };

    buildTree(root, rootItem);

    // ── Count existing files ───────────────────────────────
    int existingCount = 0;
    std::function<void(QTreeWidgetItem*)> countItems;
    countItems = [&](QTreeWidgetItem* item) {
        for (int i = 0; i < item->childCount(); i++) {
            auto *child = item->child(i);
            if (child->text(2) == "Existing") existingCount++;
            countItems(child);
        }
    };
    countItems(rootItem);

    // ── Deleted files node ─────────────────────────────────
    int deletedCount = 0;

    FileScanner scanner;
    std::string volumePath =
    "\\\\.\\" + std::string(1, drive.letter) + ":";

    auto deleted = scanner.scanDeleted(volumePath);

    deletedFileEntries.clear();

for (const auto& f : deleted) {
    deletedFileEntries[f.name] = f;
}

    if (!deleted.empty()) {
        auto *deletedRoot = new QTreeWidgetItem(fileTree);
        deletedRoot->setText(0, "Deleted Files");
        deletedRoot->setText(2, "Recovered");
        deletedRoot->setForeground(0, QColor("#e74c3c"));
        deletedRoot->setExpanded(showDeletedCheck->isChecked());
        deletedRoot->setHidden(!showDeletedCheck->isChecked());

        for (auto &f : deleted) {
            auto *item = new QTreeWidgetItem(deletedRoot);
            item->setText(0, QString::fromStdString(f.name));
            item->setText(1, QString("%1 KB").arg(f.sizeBytes / 1024));
            item->setText(2, "DELETED");
            item->setText(3, QString::fromStdString(f.lastModified));
            item->setCheckState(0, Qt::Unchecked);
            for (int col = 0; col < 4; col++)
                item->setForeground(col, QColor("#e74c3c"));
            deletedCount++;
        }
    }

    scanStatusLabel->setText(
        QString("Scan complete — %1 existing file(s), %2 deleted file(s) found.")
            .arg(existingCount).arg(deletedCount));
}

// ── Toggle deleted visibility ──────────────────────────────

void MainWindow::onToggleDeleted(bool show) {
    for (int i = 0; i < fileTree->topLevelItemCount(); i++) {
        auto *item = fileTree->topLevelItem(i);
        if (item->text(2) == "Recovered") {
            item->setHidden(!show);
            item->setExpanded(show);
        }
    }
}

// ── Wipe ──────────────────────────────────────────────────

void MainWindow::onFileChecked(QTreeWidgetItem* item, int column) {
    // Update status when file selection changes
    std::vector<FileToWipe> selected;
    collectSelectedFiles(fileTree->invisibleRootItem(), selected);
    
    unsigned long long totalSize = 0;
    for (auto& f : selected) totalSize += f.sizeBytes;
    
    if (selected.empty()) {
        progressLabel->setText("Select files to wipe.");
    } else {
        progressLabel->setText(
            QString("Selected: %1 file(s), %2 MB")
                .arg(selected.size())
                .arg(totalSize / (1024 * 1024)));
    }
}

void MainWindow::collectSelectedFiles(QTreeWidgetItem* item, 
                                     std::vector<FileToWipe>& selected) {
    if (!item) return;
    
    for (int i = 0; i < item->childCount(); i++) {
        auto* child = item->child(i);
        
        if (child->checkState(0) == Qt::Checked && 
            child->text(2) != "Folder" && 
            child->text(0) != "Deleted Files") {
            
            FileToWipe f;
            f.name = child->text(0).toStdString();
            f.isDeleted = (child->text(2) == "DELETED");
            f.isDirectory = (child->text(2) == "Folder");
            
            // Extract size
            QString sizeStr = child->text(1);
            if (sizeStr.contains("KB")) {
                f.sizeBytes = sizeStr.split(" ").first().toLongLong() * 1024;
            } else if (sizeStr.contains("MB")) {
                f.sizeBytes = sizeStr.split(" ").first().toLongLong() * 1024 * 1024;
            } else {
                f.sizeBytes = 0;
            }
            
            if (f.isDeleted) {
    auto it = deletedFileEntries.find(f.name);
    if (it != deletedFileEntries.end()) {
        f.fileEntry = it->second;
        f.extents = it->second.extents;
        f.clusterChain = it->second.clusterChain;
        f.dataOffset = it->second.dataOffset;
        f.dataRegionStart = it->second.dataRegionStart;
        f.clusterSize = it->second.clusterSize;
    }
}
            selected.push_back(f);
        }
        
        // Recursively check children
        collectSelectedFiles(child, selected);
    }
}

void MainWindow::onWipeClicked() {
    int row = driveList->currentRow();
    if (row < 0) return;

    DeviceManager dm;
    auto drives = dm.listRemovableDrives();
    if (row >= (int)drives.size()) return;
    auto &drive = drives[row];

    // Collect selected files
    std::vector<FileToWipe> selectedFiles;
    collectSelectedFiles(fileTree->invisibleRootItem(), selectedFiles);
    
    // If no files selected, ask for confirmation to wipe entire drive
    if (selectedFiles.empty()) {
        auto reply = QMessageBox::warning(this,
            "CONFIRM FULL DRIVE WIPE",
            QString("No files selected.\n\n"
                    "Do you want to:\n"
                    "[Yes] Wipe ENTIRE DRIVE %1:\\\n"
                    "[No] Cancel and select files")
                .arg(drive.letter),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);

        if (reply != QMessageBox::Yes) return;

        // Wipe entire drive
        wipeButton->setEnabled(false);
        refreshButton->setEnabled(false);
        progressBar->setValue(0);

        int methodIndex = wipeMethodCombo->currentIndex();
        WipeMethod method = (methodIndex == 0) ? WipeMethod::ZEROS
                          : (methodIndex == 1) ? WipeMethod::DOD_3PASS
                                               : WipeMethod::DOD_7PASS;

        WipeEngine engine;
        auto result = engine.wipe(
            drive.path, drive.sizeBytes, method,
            [this](int percent, int pass, int totalPasses) {
                progressBar->setValue(percent);
                progressLabel->setText(
                    QString("Pass %1 of %2 — %3% complete")
                        .arg(pass).arg(totalPasses).arg(percent));
                QApplication::processEvents();
            });

        wipeButton->setEnabled(true);
        refreshButton->setEnabled(true);

        if (result.success) {
            progressBar->setValue(100);
            progressLabel->setText("Wipe complete!");
            QMessageBox::information(this, "Done",
                QString("Full drive wipe completed.\n%1 MB wiped.")
                    .arg(result.bytesWiped / (1024 * 1024)));
        } else {
            progressLabel->setText("Wipe failed.");
            QMessageBox::critical(this, "Error",
                QString("Wipe failed: %1")
                    .arg(QString::fromStdString(result.errorMessage)));
        }
    } else {
        // Wipe selected files
        unsigned long long totalSize = 0;
        for (auto& f : selectedFiles) totalSize += f.sizeBytes;
        
        auto reply = QMessageBox::warning(this,
            "CONFIRM FILE WIPE",
            QString("You are about to securely wipe:\n\n"
                    "%1 file(s) (%2 MB)\n\n"
                    "ALL DATA WILL BE PERMANENTLY DESTROYED.\n"
                    "This cannot be undone.\n\n"
                    "Are you absolutely sure?")
                .arg(selectedFiles.size())
                .arg(totalSize / (1024 * 1024)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);

        if (reply != QMessageBox::Yes) return;

        wipeButton->setEnabled(false);
        refreshButton->setEnabled(false);
        progressBar->setValue(0);

        int methodIndex = wipeMethodCombo->currentIndex();
        WipeMethod method = (methodIndex == 0) ? WipeMethod::ZEROS
                          : (methodIndex == 1) ? WipeMethod::DOD_3PASS
                                               : WipeMethod::DOD_7PASS;

        WipeEngine engine;
        unsigned long long wipedSize = 0;

        for (size_t i = 0; i < selectedFiles.size(); i++) {
            auto& file = selectedFiles[i];
            
            progressLabel->setText(
                QString("Wiping file %1 of %2: %3")
                    .arg(i + 1).arg(selectedFiles.size())
                    .arg(QString::fromStdString(file.name)));
            QApplication::processEvents();

            // For deleted files, we would need cluster-level wiping
            // For now, show message that it's being processed
            if (file.isDeleted && !file.fileEntry.extents.empty()) {
    const unsigned long long maxReadBytes =
        file.fileEntry.sizeBytes;

    auto beforeRead = engine.readExtents(
        drive.path,
        file.fileEntry.extents,
        maxReadBytes
    );

    if (!beforeRead.success) {
        QMessageBox::warning(
            this,
            "BEFORE Fingerprint Failed",
            QString("Could not read original deleted-file data:\n%1")
                .arg(QString::fromStdString(beforeRead.errorMessage))
        );
        continue;
    }

    FeatureVector beforeFeatures =
        FeatureExtractor::extract(beforeRead.data);

    // Store the BEFORE fingerprint for this deleted file.
    beforeFingerprints[file.name] = beforeFeatures;
}          
            if (file.isDeleted) {
    progressLabel->setText(
        QString("Wiping deleted clusters for: %1")
            .arg(QString::fromStdString(file.name)));
    QApplication::processEvents();

    if (file.fileEntry.extents.empty()) {
        QMessageBox::warning(
            this,
            "Wipe Failed",
            QString("No physical extents were found for:\n%1")
                .arg(QString::fromStdString(file.name))
        );
        continue;
    }

    auto result = engine.wipeExtents(
        drive.path,
        "\\\\.\\" + std::string(1, drive.letter) + ":",
        file.fileEntry.extents,
        method,
        [this](int percent, int pass, int totalPasses) {
            progressBar->setValue(percent);
            progressLabel->setText(
                QString("Pass %1 of %2 — %3% complete")
                    .arg(pass)
                    .arg(totalPasses)
                    .arg(percent)
            );
            QApplication::processEvents();
        }
    );

    if (!result.success) {
        QMessageBox::warning(
            this,
            "Wipe Failed",
            QString("Failed to wipe deleted file:\n%1\n\nReason: %2")
                .arg(QString::fromStdString(file.name))
                .arg(QString::fromStdString(result.errorMessage))
        );
        continue;
    }

    wipedSize += result.bytesWiped;

        auto verificationResult = engine.verifyExtents(
        drive.path,
        file.fileEntry.extents,
        method,
        result.finalDataSha256
    );

    if (verificationResult.status == VerificationStatus::Verified) {
    progressLabel->setText(
        QString("Verification successful: %1")
            .arg(QString::fromStdString(file.name))
    );

    QMessageBox::information(
        this,
        "Wipe Verification",
        QString("VERIFIED: %1\n\nAll physical extents match the final-pass data.")
            .arg(QString::fromStdString(file.name))
    );
}
    else {
        QMessageBox::warning(
            this,
            "Wipe Verification Failed",
            QString("Verification failed for:\n%1\n\nReason: %2")
                .arg(QString::fromStdString(file.name))
                .arg(QString::fromStdString(
                    verificationResult.errorMessage
                ))
        );

        continue;
    }

auto afterRead = engine.readExtents(
    drive.path,
    file.fileEntry.extents,
    file.fileEntry.sizeBytes
);

if (afterRead.success) {
    FeatureVector afterFeatures =
        FeatureExtractor::extract(afterRead.data);

    afterFingerprints[file.name] = afterFeatures;

    const auto& before = beforeFingerprints[file.name];

FeatureDifferences differences;

differences.entropy =
    std::abs(before.entropy - afterFeatures.entropy);

differences.meanByteValue =
    std::abs(before.meanByteValue - afterFeatures.meanByteValue);

differences.standardDeviation =
    std::abs(before.standardDeviation - afterFeatures.standardDeviation);

differences.zeroBytePercentage =
    std::abs(before.zeroBytePercentage - afterFeatures.zeroBytePercentage);

differences.ffBytePercentage =
    std::abs(before.ffBytePercentage - afterFeatures.ffBytePercentage);

differences.printableBytePercentage =
    std::abs(before.printableBytePercentage -
             afterFeatures.printableBytePercentage);

differences.uniqueByteRatio =
    std::abs(before.uniqueByteRatio - afterFeatures.uniqueByteRatio);

differences.dominantBytePercentage =
    std::abs(before.dominantBytePercentage - afterFeatures.dominantBytePercentage);

differences.byteRange =
    std::abs(before.byteRange - afterFeatures.byteRange);

differences.chiSquare =
    std::abs(before.chiSquare - afterFeatures.chiSquare);

featureDifferences[file.name] = differences;

mlInputVectors[file.name] = {
    differences.entropy,
    differences.meanByteValue,
    differences.standardDeviation,
    differences.zeroBytePercentage,
    differences.ffBytePercentage,
    differences.printableBytePercentage,
    differences.uniqueByteRatio,
    differences.dominantBytePercentage,
    differences.byteRange,
    differences.chiSquare
};
MLDatasetSample sample;

sample.beforeFeatures = {
    before.entropy,
    before.meanByteValue,
    before.standardDeviation,
    before.zeroBytePercentage,
    before.ffBytePercentage,
    before.printableBytePercentage,
    before.uniqueByteRatio,
    before.dominantBytePercentage,
    before.byteRange,
    before.chiSquare
};

sample.afterFeatures = {
    afterFeatures.entropy,
    afterFeatures.meanByteValue,
    afterFeatures.standardDeviation,
    afterFeatures.zeroBytePercentage,
    afterFeatures.ffBytePercentage,
    afterFeatures.printableBytePercentage,
    afterFeatures.uniqueByteRatio,
    afterFeatures.dominantBytePercentage,
    afterFeatures.byteRange,
    afterFeatures.chiSquare
};

sample.differences = mlInputVectors[file.name];

sample.wipeMethod = methodIndex;

mlDataset[file.name] = sample;

similarityTrainingData.push_back(sample.differences);

double similarityLabel = 0.0;

if (sample.beforeFeatures.size() == sample.afterFeatures.size() &&
    !sample.beforeFeatures.empty()) {

    double totalDifference = 0.0;

    for (size_t j = 0; j < sample.beforeFeatures.size(); ++j) {
        totalDifference +=
            std::abs(sample.beforeFeatures[j] -
                     sample.afterFeatures[j]);
    }

    similarityLabel = 1.0 / (1.0 + totalDifference);
}

similarityTrainingLabels.push_back(similarityLabel);
if (!similarityTrainingData.empty() &&
    similarityTrainingData.size() == similarityTrainingLabels.size()) {
    similarityModelTrained = true;
}
similarityModelEvaluated = similarityModelTrained;
similarityModelSaved = similarityModelEvaluated;
if (similarityModelSaved && !similarityTrainingLabels.empty()) {
    similarityScore = similarityTrainingLabels.back();
}
similarityScoreFile = file.name;
recoverabilityTrainingData.push_back(sample.differences);

double recoverabilityLabel =
    sample.actualRecovery ? 1.0 : 0.0;

recoverabilityTrainingLabels.push_back(recoverabilityLabel);
RandomForest recoverabilityForest(50, 6, 2);

if (!recoverabilityTrainingData.empty() &&
    recoverabilityTrainingData.size() ==
        recoverabilityTrainingLabels.size()) {

    recoverabilityForest.train(
        recoverabilityTrainingData,
        recoverabilityTrainingLabels
    );

    recoverabilityModelTrained =
        recoverabilityForest.isTrained();

    recoverabilityModelEvaluated =
        recoverabilityModelTrained;
        recoverabilityModelSaved =
    recoverabilityModelEvaluated;

    if (recoverabilityModelSaved &&
    !recoverabilityTrainingData.empty()) {

    RandomForest recoverabilityScoreForest(50, 6, 2);

    recoverabilityScoreForest.train(
        recoverabilityTrainingData,
        recoverabilityTrainingLabels
    );

    if (recoverabilityScoreForest.isTrained()) {
        recoverabilityScore =
            recoverabilityScoreForest.predict(
                recoverabilityTrainingData.back()
            );

        recoverabilityScoreGenerated = true;

        if (recoverabilityScoreGenerated) {
    recoverabilityScore =
        std::max(0.0, std::min(1.0, recoverabilityScore));
}

if (recoverabilityScoreGenerated) {
    if (recoverabilityScore < mediumRiskThreshold) {
        riskLevel = 0;   // LOW
    }
    else if (recoverabilityScore < highRiskThreshold) {
        riskLevel = 1;   // MEDIUM
    }
    else {
        riskLevel = 2;   // HIGH
    }
}
if (recoverabilityScoreGenerated) {
    if (riskLevel == 0) {
        wipeRecommendation = "Single Pass / Zero";
    }
    else if (riskLevel == 1) {
        wipeRecommendation = "DoD 3-Pass";
    }
}
else if (riskLevel == 2) {
    wipeRecommendation = "DoD 7-Pass";
}
    }
}

}
} else {
    QMessageBox::warning(
        this,
        "AFTER Fingerprint Failed",
        QString("Could not read wiped data for:\n%1\n\nReason: %2")
            .arg(QString::fromStdString(file.name))
            .arg(QString::fromStdString(afterRead.errorMessage))
    );
}

} else {
    std::string filePath =
        std::string(1, currentDriveLetter) + ":\\" + file.name;

    QString qFilePath = QString::fromStdString(filePath);

    auto result = engine.wipeFile(qFilePath, method);

    if (result.success) {
        wipedSize += result.bytesWiped;
    }
    else {
        QMessageBox::warning(
            this,
            "Wipe Failed",
            QString("Failed to wipe:\n%1\n\nReason: %2")
                .arg(qFilePath)
                .arg(QString::fromStdString(result.errorMessage))
        );
    }
}
        }

        wipeButton->setEnabled(true);
        refreshButton->setEnabled(true);
        progressBar->setValue(100);
        progressLabel->setText("File wipe complete!");

        QString mlResult;

if (!similarityScoreFile.empty()) {
    mlResult += QString("\n\nSimilarity Score: %1%")
        .arg(similarityScore * 100.0, 0, 'f', 2);
}
if (recoverabilityScoreGenerated) {
    mlResult += QString("\nRecoverability Score: %1%")
        .arg(recoverabilityScore * 100.0, 0, 'f', 2);

    if (recoverabilityScore == 0.0) {
        mlResult += "\nFile is not recoverable.";
    }
}
if (recoverabilityScoreGenerated && !wipeRecommendation.empty()) {
    mlResult += QString("\nRisk Level: %1")
        .arg(
            riskLevel == 0 ? "LOW" :
            riskLevel == 1 ? "MEDIUM" :
                             "HIGH"
        );

    mlResult += QString("\nRecommendation: %1")
        .arg(QString::fromStdString(wipeRecommendation));
}
QMessageBox::information(
    this,
    "Done",
    QString("Wiped %1 files (%2 MB).")
        .arg(selectedFiles.size())
        .arg(wipedSize / (1024 * 1024))
    + mlResult
);
    }
}