#include "MainWindow.h"
#include "DeviceManager.h"
#include "FileScanner.h"
#include "WipeEngine.h"
#include "RandomForest.h"
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
#include <QTimer>
#include <QTextBrowser>
#include <QProcessEnvironment>
#include <QProcess>
#include <QMap>
#include <QLineEdit>
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
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QFile>
#include <QSaveFile>
#include <QDesktopServices>
#include <QUrl>
#include <QUuid>
#include <QCryptographicHash>
#include <QFileInfo>
#include <QDateTime>
#include <QTimeZone>
#include <QColor>
#include <QDir>
#include <QPdfWriter>
#include <QTextDocument>
#include <QPageSize>
#include <QPageLayout>
#include <map>
#include <algorithm>
#include <cmath>
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

QString auditRootPath()
{
    QString root = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (root.isEmpty())
        root = QDir::home().filePath(QStringLiteral(".dataguard"));
    QDir().mkpath(root);
    QDir().mkpath(QDir(root).filePath(QStringLiteral("Certificates")));
    return root;
}
QJsonArray readAuditRecords()
{
    QFile file(QDir(auditRootPath()).filePath(QStringLiteral("activity_log.json")));
    if (!file.open(QIODevice::ReadOnly)) return QJsonArray();
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    return document.isArray() ? document.array() : QJsonArray();
}
bool writeAuditRecords(const QJsonArray& records)
{
    const QString path = QDir(auditRootPath()).filePath(QStringLiteral("activity_log.json"));
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) return false;
    const QByteArray bytes = QJsonDocument(records).toJson(QJsonDocument::Indented);
    if (file.write(bytes) != bytes.size()) { file.cancelWriting(); return false; }
    return file.commit();
}
QString auditRecordDigest(QJsonObject record)
{
    record.remove(QStringLiteral("recordDigestSha256"));
    const QByteArray bytes = QJsonDocument(record).toJson(QJsonDocument::Compact);
    return QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
}
QString displayTimestamp(const QJsonObject& record)
{
    const QString raw = record.value(QStringLiteral("timestamp")).toString().trimmed();
    if (raw.endsWith(QStringLiteral("IST"))) return raw;
    QDateTime parsed = QDateTime::fromString(raw, Qt::ISODateWithMs);
    if (!parsed.isValid()) parsed = QDateTime::fromString(raw, Qt::ISODate);
    if (!parsed.isValid()) return raw.isEmpty() ? QStringLiteral("Time not recorded") : raw;
    const QTimeZone ist(QByteArrayLiteral("Asia/Kolkata"));
    if (parsed.timeSpec() == Qt::LocalTime) parsed = parsed.toUTC();
    return parsed.toTimeZone(ist).toString(QStringLiteral("dd MMM yyyy, hh:mm:ss AP 'IST'"));
}
QString readableOutcome(const QJsonObject& record)
{
    if (record.value(QStringLiteral("status")).toString() != QStringLiteral("SUCCESS"))
        return QStringLiteral("Wipe failed / not completed");
    if (record.value(QStringLiteral("verification")).toString().startsWith(QStringLiteral("PASSED")))
        return QStringLiteral("Wiped successfully (verified)");
    return QStringLiteral("Wiped successfully");
}
QString readableVerification(const QJsonObject& record)
{
    const QString value = record.value(QStringLiteral("verification")).toString();
    if (value.startsWith(QStringLiteral("PASSED"))) return QStringLiteral("Verification successful");
    if (value.startsWith(QStringLiteral("FAILED"))) return QStringLiteral("Verification failed");
    if (record.value(QStringLiteral("status")).toString() != QStringLiteral("SUCCESS"))
        return QStringLiteral("Not completed");
    return QStringLiteral("Not reported by this operation");
}
QString readableMethod(const QJsonObject& record)
{
    const int passes = record.value(QStringLiteral("passes")).toString().toInt();
    if (passes == 1) return QStringLiteral("Single pass (zero fill)");
    if (passes == 3) return QStringLiteral("Three passes (DoD)");
    if (passes == 7) return QStringLiteral("Seven passes (DoD)");
    const QString method = record.value(QStringLiteral("method")).toString();
    return method.isEmpty() ? QStringLiteral("Not recorded") : method;
}
QString mlTableSummary(const QJsonObject& record)
{
    const QString raw = record.value(QStringLiteral("mlResults")).toString().trimmed();
    if (raw.isEmpty()) return QStringLiteral("ML analysis not available");

    // Historical rows created by the prior unnormalized formula / synthetic recovery labels
    // are preserved for audit, but must not be presented as valid current ML results.
    const bool containsOldSimilarity = raw.contains(QStringLiteral("Similarity score:"), Qt::CaseInsensitive);
    const bool containsNormalizedSimilarity = raw.contains(
        QStringLiteral("normalized before/after feature comparison"), Qt::CaseInsensitive);
    if (containsOldSimilarity && !containsNormalizedSimilarity) {
        return QStringLiteral("Legacy result — previous score is not valid; use a new operation for updated analysis");
    }

    const QStringList lines = raw.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    QStringList clean;
    for (const QString& sourceLine : lines) {
        const QString line = sourceLine.trimmed();
        const QString lower = line.toLower();
        if (lower.startsWith(QStringLiteral("similarity score")) ||
            lower.startsWith(QStringLiteral("recoverability score")) ||
            lower.startsWith(QStringLiteral("recoverability risk")) ||
            lower.startsWith(QStringLiteral("risk level")) ||
            lower.startsWith(QStringLiteral("recommended next wipe method")) ||
            lower.startsWith(QStringLiteral("recommendation:")))
            clean << line;
    }
    return clean.isEmpty() ? QStringLiteral("ML analysis details available on hover") : clean.join(QStringLiteral("\n"));
}
QString conciseLocation(const QJsonObject& record)
{
    const QString raw = record.value(QStringLiteral("filePath")).toString().trimmed();
    if (raw.isEmpty()) return QStringLiteral("Location not recorded");
    const QString fileName = record.value(QStringLiteral("fileName")).toString().trimmed();
    const QString source = record.value(QStringLiteral("source")).toString();
    QString drive = record.value(QStringLiteral("driveLetter")).toString().trimmed();
    drive.remove(QLatin1Char(':'));
    if (source.contains(QStringLiteral("Deleted Files"), Qt::CaseInsensitive) ||
        raw.contains(QStringLiteral("Deleted Files section"), Qt::CaseInsensitive)) {
        if (drive.isEmpty()) {
            const int marker = raw.indexOf(QStringLiteral("drive "), 0, Qt::CaseInsensitive);
            if (marker >= 0 && marker + 6 < raw.size()) drive = raw.mid(marker + 6, 1);
        }
        return drive.isEmpty() ? QStringLiteral("Deleted Files > %1").arg(fileName)
            : QStringLiteral("Drive %1: > Deleted Files > %2").arg(drive, fileName);
    }
    QString cleaned = raw;
    const int scanner = cleaned.indexOf(QStringLiteral("; scanner path:"), 0, Qt::CaseInsensitive);
    if (scanner >= 0) cleaned.truncate(scanner);
    const int physical = cleaned.indexOf(QStringLiteral("; physical extents:"), 0, Qt::CaseInsensitive);
    if (physical >= 0) cleaned.truncate(physical);
    cleaned = cleaned.trimmed();
    if (cleaned.contains(QStringLiteral(":\\"))) {
        QString p = QDir::fromNativeSeparators(cleaned);
        const QString driveLetter = p.left(1).toUpper();
        p = p.mid(3);
        p.replace(QLatin1Char('/'), QLatin1Char('>'));
        QStringList parts = p.split(QLatin1Char('>'), Qt::SkipEmptyParts);
        for (QString& part : parts) part = part.trimmed();
        return QStringLiteral("Drive %1:").arg(driveLetter) +
            (parts.isEmpty() ? QString() : QStringLiteral(" > ") + parts.join(QStringLiteral(" > ")));
    }
    return cleaned;
}


QString certificateHtml(const QJsonObject& record)
{
    auto field = [&record](const QString& label, const QString& key) {
        return QStringLiteral("<tr><th>%1</th><td>%2</td></tr>")
            .arg(label.toHtmlEscaped(), record.value(key).toString().toHtmlEscaped());
    };
    auto escLines = [](const QString& value) {
        return value.toHtmlEscaped().replace(QStringLiteral("\n"), QStringLiteral("<br>"));
    };
    QString ml = mlTableSummary(record);
    if (ml == QStringLiteral("ML analysis details available on hover"))
        ml = QStringLiteral("ML analysis was not reported for this operation.");
    const QString errors = record.value(QStringLiteral("errorMessage")).toString().trimmed();
    const QString id = record.value(QStringLiteral("certificateId")).toString();
    const QString result = readableOutcome(record);
    const QString verification = readableVerification(record);
    const QString method = readableMethod(record);
    QString html = QStringLiteral(R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DataGuard Secure Wipe Certificate</title>
<style>
*{box-sizing:border-box}body{font-family:"Segoe UI",Arial,sans-serif;background:#eef2f7;color:#182536;margin:0;padding:32px}
main{max-width:960px;margin:0 auto;background:#fff;border-top:7px solid #1677c8;padding:34px 42px;box-shadow:0 8px 28px #18253620}
h1{margin:0;color:#132c47;font-size:28px}.subtitle{color:#53677e;margin:8px 0 22px}
.badge{display:inline-block;border-radius:5px;padding:7px 12px;font-weight:800;background:#e8f5eb;color:#176c3a}
.badge.failed{background:#fde9e9;color:#a11d2b}.id{background:#f1f5f9;border:1px solid #d8e0ea;padding:12px;margin:18px 0;font-family:Consolas,monospace;overflow-wrap:anywhere}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.7px;color:#1b5b8f;margin-top:28px;border-bottom:2px solid #d9e7f3;padding-bottom:8px}
table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{padding:11px 12px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{width:30%;background:#f5f8fb;color:#32485e}td{color:#182536;white-space:normal}
.notes{border-left:4px solid #1677c8;background:#f3f8fc;padding:14px;line-height:1.75;overflow-wrap:anywhere}
footer{margin-top:30px;border-top:1px solid #dae2ea;padding-top:18px;color:#596a7c;font-size:12px;line-height:1.55}
@media print{body{padding:0;background:#fff}main{box-shadow:none;max-width:none;border:0;padding:16mm}}
</style></head><body><main>
<h1>DataGuard — Certificate of Secure Data Wipe</h1>
<div class="subtitle">Operation record · Secure. Recover. Verify.</div>
)HTML");
    const bool success = record.value(QStringLiteral("status")).toString() == QStringLiteral("SUCCESS");
    html += QStringLiteral("<p><span class=\"badge%1\">%2</span></p>")
        .arg(success ? QString() : QStringLiteral(" failed"), result.toHtmlEscaped());
    html += QStringLiteral("<div class=\"id\"><strong>Certificate ID:</strong> %1</div>").arg(id.toHtmlEscaped());
    html += QStringLiteral("<h2>Who and when</h2><table>");
    html += field(QStringLiteral("Signed-in user"), QStringLiteral("user"));
    html += QStringLiteral("<tr><th>Date and time (Indian Standard Time)</th><td>%1</td></tr>")
        .arg(displayTimestamp(record).toHtmlEscaped());
    html += QStringLiteral("</table><h2>What was wiped</h2><table>");
    html += field(QStringLiteral("File or drive"), QStringLiteral("fileName"));
    html += QStringLiteral("<tr><th>Location</th><td>%1</td></tr>").arg(conciseLocation(record).toHtmlEscaped());
    html += QStringLiteral("</table><h2>Wipe details</h2><table>");
    html += QStringLiteral("<tr><th>Method used</th><td>%1</td></tr>").arg(method.toHtmlEscaped());
    html += QStringLiteral("<tr><th>Number of passes</th><td>%1</td></tr>")
        .arg(record.value(QStringLiteral("passes")).toString().toHtmlEscaped());
    html += QStringLiteral("<tr><th>Result</th><td>%1</td></tr>").arg(result.toHtmlEscaped());
    html += QStringLiteral("<tr><th>Verification</th><td>%1</td></tr>").arg(verification.toHtmlEscaped());
    html += QStringLiteral("</table><h2>Machine-learning analysis</h2><div class=\"notes\">%1</div>")
        .arg(escLines(ml));
    html += QStringLiteral("<p style=\"color:#53677e;font-size:12px\">Similarity measures feature similarity before and after wiping. Recoverability is an ML estimate, not a guarantee.</p>");
    if (!errors.isEmpty())
        html += QStringLiteral("<h2>Additional information</h2><div class=\"notes\">%1</div>").arg(escLines(errors));
    html += QStringLiteral(R"HTML(<footer>
This certificate summarizes the result reported by the local DataGuard application. ML scores are model estimates, not guarantees of data recovery or permanent erasure. Keep the certificate together with the application activity log for audit purposes.
</footer></main></body></html>)HTML");
    return html;
}

bool writeCertificatePdf(const QString& pdfPath, const QJsonObject& record)
{
    const QFileInfo info(pdfPath);
    if (!QDir().mkpath(info.absolutePath()))
        return false;

    {
        QPdfWriter writer(pdfPath);
        writer.setTitle(QStringLiteral("DataGuard Wipe Certificate - %1")
            .arg(record.value(QStringLiteral("certificateId")).toString()));
        writer.setCreator(QStringLiteral("DataGuard Secure Data Wiping System"));
        writer.setResolution(120);
        writer.setPageSize(QPageSize(QPageSize::A4));
        writer.setPageMargins(QMarginsF(14, 14, 14, 14), QPageLayout::Millimeter);

        QTextDocument document;
        document.setDocumentMargin(0.0);
        document.setHtml(certificateHtml(record));
        document.print(&writer);
    }

    const QFileInfo written(pdfPath);
    return written.exists() && written.isFile() && written.size() > 0;
}

void styleAuditTable(QTableWidget* table)
{
    table->setAlternatingRowColors(true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setWordWrap(true);
    table->setTextElideMode(Qt::ElideRight);
    table->verticalHeader()->setVisible(false);
    table->verticalHeader()->setDefaultSectionSize(56);
    table->setShowGrid(true);
    table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    table->setStyleSheet(QStringLiteral(
        "QTableWidget { color:#f4f8ff; background:rgba(2,11,29,235); alternate-background-color:rgba(14,30,49,235); gridline-color:rgba(122,177,211,75); border:1px solid rgba(122,177,211,90); border-radius:8px; selection-background-color:#263b52; selection-color:#ffffff; font-size:12px; } "
        "QTableWidget::item { color:#f4f8ff; padding:7px; } "
        "QHeaderView::section { color:#ffffff; background:#192d45; border:0; border-right:1px solid rgba(122,177,211,70); border-bottom:1px solid rgba(122,177,211,85); padding:9px 7px; font-weight:700; } "
        "QTableCornerButton::section { background:#192d45; border:0; }"));
}

QString auditPathForFile(const FileToWipe& file, char driveLetter)
{
    if (!file.fullPath.empty())
        return QString::fromStdString(file.fullPath);
    if (file.isDeleted)
        return QStringLiteral("Drive %1: > Deleted Files > %2")
            .arg(QChar(driveLetter)).arg(QString::fromStdString(file.name));
    return QStringLiteral("Drive %1: > %2")
        .arg(QChar(driveLetter)).arg(QString::fromStdString(file.name));
}

int passesForMethod(int methodIndex)
{
    return methodIndex == 0 ? 1 : (methodIndex == 1 ? 3 : 7);
}
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
    m_pages->addWidget(buildActivityLogPage());
    m_pages->addWidget(buildCertificatesPage());
    m_pages->addWidget(buildAssistantPage());
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
    refreshActivityLog(); refreshCertificates();
}
void MainWindow::setSignedInUser(const QString& username)
{
    m_signedInUser=username.trimmed();
    if(m_accountLabel)m_accountLabel->setText(m_signedInUser.isEmpty()?QStringLiteral("Signed out"):m_signedInUser);
    if(m_settingsUsername)m_settingsUsername->setText(m_signedInUser.isEmpty()?QStringLiteral("No active session"):m_signedInUser);
}
void MainWindow::navigateTo(int index,const QString& title)
{
    if (!m_pages || index < 0 || index >= m_pages->count())
        return;
    const int current = m_pages->currentIndex();
    if (index == 6 && current != 6)
        m_lastNonAssistantPageIndex = current;
    else if (index != 6)
        m_lastNonAssistantPageIndex = index;
    m_pages->setCurrentIndex(index);
    if (m_pageTitle) m_pageTitle->setText(title);
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

QWidget* MainWindow::buildActivityLogPage()
{
    auto* content = new QWidget;
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(4,4,8,8);
    layout->setSpacing(12);
    auto* card = makeCard(content);
    auto* box = new QVBoxLayout(card);
    box->setContentsMargins(16,14,16,16);
    box->setSpacing(10);
    box->addWidget(heading(QStringLiteral("Wipe Activity Log"), card));
    box->addWidget(bodyText(QStringLiteral("A readable history of who performed each wipe, when it happened (IST), which file or drive was targeted, the result, and the ML assessment."), card));
    auto* controls = new QHBoxLayout;
    controls->addStretch();
    auto* refresh = new QPushButton(QStringLiteral("Refresh Log"), card);
    stylePrimaryButton(refresh);
    connect(refresh, &QPushButton::clicked, this, &MainWindow::refreshActivityLog);
    controls->addWidget(refresh);
    box->addLayout(controls);
    m_activityTable = new QTableWidget(card);
    m_activityTable->setColumnCount(8);
    m_activityTable->setHorizontalHeaderLabels({
        QStringLiteral("Date & time (IST)"), QStringLiteral("Signed-in user"),
        QStringLiteral("File / drive"), QStringLiteral("Location"),
        QStringLiteral("Wipe method"), QStringLiteral("Result"),
        QStringLiteral("ML analysis"), QStringLiteral("Certificate ID")});
    styleAuditTable(m_activityTable);
    auto* header = m_activityTable->horizontalHeader();
    header->setSectionResizeMode(QHeaderView::Interactive);
    const int widths[] = {150,105,135,170,120,165,210,155};
    for (int i=0; i<8; ++i) m_activityTable->setColumnWidth(i,widths[i]);
    m_activityTable->setMinimumHeight(340);
    connect(m_activityTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (!m_activityTable || !m_activityTable->item(row, 0)) return;
        const QString path = m_activityTable->item(row, 0)->data(Qt::UserRole).toString();
        if (!path.isEmpty() && QFileInfo::exists(path))
            QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    box->addWidget(m_activityTable, 1);
    layout->addWidget(card, 1);
    return scrollPage(content);
}

QWidget* MainWindow::buildCertificatesPage()
{
    auto* content = new QWidget;
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(4,4,8,8);
    layout->setSpacing(12);
    auto* card = makeCard(content);
    auto* box = new QVBoxLayout(card);
    box->setContentsMargins(16,14,16,16);
    box->setSpacing(10);
    box->addWidget(heading(QStringLiteral("PDF Wipe Certificates"), card));
    box->addWidget(bodyText(QStringLiteral("Each wipe attempt has a PDF certificate named with its Certificate ID. Select a certificate and open the PDF for the full timestamp, operator, file location, wipe method, outcome, verification and ML results."), card));
    auto* controls = new QHBoxLayout;
    controls->addStretch();
    auto* refresh = new QPushButton(QStringLiteral("Refresh Certificates"), card);
    stylePrimaryButton(refresh);
    connect(refresh, &QPushButton::clicked, this, &MainWindow::refreshCertificates);
    controls->addWidget(refresh);
    auto* open = new QPushButton(QStringLiteral("Open PDF Certificate"), card);
    stylePrimaryButton(open);
    connect(open, &QPushButton::clicked, this, [this]() {
        if (!m_certificatesTable || m_certificatesTable->currentRow() < 0) {
            QMessageBox::information(this, QStringLiteral("Select a certificate"),
                QStringLiteral("Select a certificate row first."));
            return;
        }
        const int row = m_certificatesTable->currentRow();
        const QString path = m_certificatesTable->item(row, 0)
            ? m_certificatesTable->item(row, 0)->data(Qt::UserRole).toString() : QString();
        if (!path.isEmpty() && QFileInfo::exists(path))
            QDesktopServices::openUrl(QUrl::fromLocalFile(path));
        else
            QMessageBox::warning(this, QStringLiteral("PDF unavailable"),
                QStringLiteral("The PDF could not be generated. Refresh the list and check write access to the DataGuard application-data folder."));
    });
    controls->addWidget(open);
    box->addLayout(controls);
    m_certificatesTable = new QTableWidget(card);
    m_certificatesTable->setColumnCount(6);
    m_certificatesTable->setHorizontalHeaderLabels({
        QStringLiteral("Certificate ID"), QStringLiteral("PDF file name"),
        QStringLiteral("Date & time (IST)"), QStringLiteral("Signed-in user"),
        QStringLiteral("File / drive"), QStringLiteral("PDF status")});
    styleAuditTable(m_certificatesTable);
    auto* header = m_certificatesTable->horizontalHeader();
    header->setSectionResizeMode(QHeaderView::Interactive);
    const int widths[] = {205,225,165,125,190,115};
    for (int i=0; i<6; ++i) m_certificatesTable->setColumnWidth(i,widths[i]);
    m_certificatesTable->setMinimumHeight(340);
    connect(m_certificatesTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (!m_certificatesTable || !m_certificatesTable->item(row, 0)) return;
        const QString path = m_certificatesTable->item(row, 0)->data(Qt::UserRole).toString();
        if (!path.isEmpty() && QFileInfo::exists(path))
            QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    box->addWidget(m_certificatesTable, 1);
    layout->addWidget(card, 1);
    return scrollPage(content);
}

void MainWindow::refreshActivityLog()
{
    if (!m_activityTable) return;
    const QJsonArray records = readAuditRecords();
    m_activityTable->setRowCount(static_cast<int>(records.size()));
    int row = 0;
    for (int i = static_cast<int>(records.size()) - 1; i >= 0; --i, ++row) {
        const QJsonObject r = records.at(i).toObject();
        const QString certPath = r.value(QStringLiteral("certificatePath")).toString();
        const QString error = r.value(QStringLiteral("errorMessage")).toString();
        const QStringList values = {
            displayTimestamp(r),
            r.value(QStringLiteral("user")).toString(),
            r.value(QStringLiteral("fileName")).toString(),
            conciseLocation(r),
            readableMethod(r),
            readableOutcome(r),
            mlTableSummary(r),
            r.value(QStringLiteral("certificateId")).toString()
        };
        for (int col = 0; col < values.size(); ++col) {
            auto* item = new QTableWidgetItem(values.at(col));
            item->setForeground(QColor(QStringLiteral("#f4f8ff")));
            item->setToolTip(values.at(col));
            m_activityTable->setItem(row, col, item);
        }
        m_activityTable->item(row, 0)->setData(Qt::UserRole, certPath);
        m_activityTable->item(row, 5)->setForeground(QColor(
            r.value(QStringLiteral("status")).toString() == QStringLiteral("SUCCESS")
                ? QStringLiteral("#aaf0c0") : QStringLiteral("#ffb0b8")));
        if (!error.isEmpty())
            m_activityTable->item(row, 5)->setToolTip(values.at(5) + QStringLiteral("\nDetails: ") + error);
        const QString rawMl = r.value(QStringLiteral("mlResults")).toString();
        if (!rawMl.isEmpty()) m_activityTable->item(row, 6)->setToolTip(rawMl);
    }
    m_activityTable->resizeRowsToContents();
}

void MainWindow::refreshCertificates()
{
    if (!m_certificatesTable) return;
    QJsonArray records = readAuditRecords();
    bool recordsChanged = false;
    const QString certificateDirectory = QDir(auditRootPath()).filePath(QStringLiteral("Certificates"));
    QDir().mkpath(certificateDirectory);

    // Generate missing PDFs and migrate prior HTML certificate references.
    for (int i = 0; i < records.size(); ++i) {
        QJsonObject record = records.at(i).toObject();
        const QString certificateId = record.value(QStringLiteral("certificateId")).toString().trimmed();
        if (certificateId.isEmpty()) continue;

        const QString pdfPath = QDir(certificateDirectory).filePath(certificateId + QStringLiteral(".pdf"));
        bool pdfExists = QFileInfo(pdfPath).exists() && QFileInfo(pdfPath).size() > 0;
        const int templateVersion = record.value(QStringLiteral("certificateTemplateVersion")).toInt();
        bool refreshedPdf = false;
        // Regenerate prior-template PDFs so legacy ML values are clearly labelled
        // and the visible certificate uses the current report format.
        if (!pdfExists || templateVersion < 2) {
            refreshedPdf = writeCertificatePdf(pdfPath, record);
            if (refreshedPdf)
                pdfExists = true;
            else if (!pdfExists)
                pdfExists = QFileInfo(pdfPath).exists() && QFileInfo(pdfPath).size() > 0;
        }

        const QString storedPath = record.value(QStringLiteral("certificatePath")).toString();
        const QString desiredPath = pdfExists ? pdfPath : QString();
        if (pdfExists && refreshedPdf)
            record.insert(QStringLiteral("certificateTemplateVersion"), 2);
        if (storedPath != desiredPath || record.contains(QStringLiteral("certificateError")) ||
            (pdfExists && refreshedPdf && templateVersion < 2)) {
            record.insert(QStringLiteral("certificatePath"), desiredPath);
            if (pdfExists) record.remove(QStringLiteral("certificateError"));
            else record.insert(QStringLiteral("certificateError"), QStringLiteral("PDF certificate generation failed."));
            record.insert(QStringLiteral("recordDigestSha256"), auditRecordDigest(record));
            records.replace(i, record);
            recordsChanged = true;
        }
    }
    if (recordsChanged && !writeAuditRecords(records)) {
        QMessageBox::warning(this, QStringLiteral("Certificate index update failed"),
            QStringLiteral("PDF files may exist, but the certificate index could not be updated. Check write access to the DataGuard application-data folder."));
    }

    m_certificatesTable->setRowCount(static_cast<int>(records.size()));
    int row = 0;
    for (int i = static_cast<int>(records.size()) - 1; i >= 0; --i, ++row) {
        const QJsonObject record = records.at(i).toObject();
        const QString certificateId = record.value(QStringLiteral("certificateId")).toString();
        const QString pdfPath = record.value(QStringLiteral("certificatePath")).toString();
        const bool pdfAvailable = !pdfPath.isEmpty() &&
            QFileInfo(pdfPath).exists() && QFileInfo(pdfPath).size() > 0;
        const QStringList values = {
            certificateId,
            certificateId.isEmpty() ? QStringLiteral("—") : certificateId + QStringLiteral(".pdf"),
            displayTimestamp(record),
            record.value(QStringLiteral("user")).toString(),
            record.value(QStringLiteral("fileName")).toString(),
            pdfAvailable ? QStringLiteral("PDF ready") : QStringLiteral("PDF unavailable")
        };
        for (int col = 0; col < values.size(); ++col) {
            auto* item = new QTableWidgetItem(values.at(col));
            item->setForeground(QColor(QStringLiteral("#f4f8ff")));
            item->setToolTip(values.at(col));
            m_certificatesTable->setItem(row, col, item);
        }
        m_certificatesTable->item(row, 0)->setData(Qt::UserRole, pdfPath);
        m_certificatesTable->item(row, 5)->setForeground(QColor(
            pdfAvailable ? QStringLiteral("#aaf0c0") : QStringLiteral("#ffb0b8")));
        const QString ml = record.value(QStringLiteral("mlResults")).toString();
        if (!ml.isEmpty()) m_certificatesTable->item(row, 4)->setToolTip(
            record.value(QStringLiteral("fileName")).toString() + QStringLiteral("\nML: ") + ml);
    }
    m_certificatesTable->resizeRowsToContents();
}

void MainWindow::recordWipeActivity(const QString& fileName, const QString& filePath,
                                    const QString& source, const QString& driveLetter,
                                    const QString& physicalDevicePath, const QString& deviceModel,
                                    const QString& method, int passes, bool success,
                                    const QString& verification, unsigned long long bytesWiped,
                                    const QString& mlResults, const QString& errorMessage)
{
    const QTimeZone ist(QByteArrayLiteral("Asia/Kolkata"));
    const QDateTime nowIst = QDateTime::currentDateTimeUtc().toTimeZone(ist);
    const QString timestamp = nowIst.toString(QStringLiteral("dd MMM yyyy, hh:mm:ss AP 'IST'"));
    const QString certificateId = QStringLiteral("DG-%1-%2")
        .arg(nowIst.toString(QStringLiteral("yyyyMMdd-HHmmss-zzz")),
             QUuid::createUuid().toString(QUuid::WithoutBraces).left(8).toUpper());
    const QString certificateDirectory = QDir(auditRootPath()).filePath(QStringLiteral("Certificates"));
    QDir().mkpath(certificateDirectory);
    const QString certificatePath = QDir(certificateDirectory).filePath(certificateId + QStringLiteral(".pdf"));

    QJsonObject record;
    record.insert(QStringLiteral("timestamp"), timestamp);
    record.insert(QStringLiteral("user"), m_signedInUser.trimmed().isEmpty()
        ? QStringLiteral("Unknown / no active session") : m_signedInUser.trimmed());
    record.insert(QStringLiteral("fileName"), fileName);
    record.insert(QStringLiteral("filePath"), filePath);
    record.insert(QStringLiteral("source"), source);
    record.insert(QStringLiteral("driveLetter"), driveLetter);
    record.insert(QStringLiteral("physicalDevicePath"), physicalDevicePath);
    record.insert(QStringLiteral("deviceModel"), deviceModel);
    record.insert(QStringLiteral("method"), method);
    record.insert(QStringLiteral("passes"), QString::number(passes));
    record.insert(QStringLiteral("status"), success ? QStringLiteral("SUCCESS") : QStringLiteral("FAILED"));
    record.insert(QStringLiteral("verification"), verification);
    record.insert(QStringLiteral("bytesWiped"), QString::number(bytesWiped));
    record.insert(QStringLiteral("mlResults"), mlResults);
    record.insert(QStringLiteral("errorMessage"), errorMessage);
    record.insert(QStringLiteral("certificateId"), certificateId);
    record.insert(QStringLiteral("certificatePath"), certificatePath);
    record.insert(QStringLiteral("certificateTemplateVersion"), 2);
    record.insert(QStringLiteral("recordDigestSha256"), auditRecordDigest(record));

    const bool certificateSaved = writeCertificatePdf(certificatePath, record);
    if (!certificateSaved) {
        record.insert(QStringLiteral("certificatePath"), QString());
        record.insert(QStringLiteral("certificateError"), QStringLiteral("PDF certificate could not be written."));
        record.insert(QStringLiteral("recordDigestSha256"), auditRecordDigest(record));
    }

    QJsonArray records = readAuditRecords();
    records.append(record);
    if (!writeAuditRecords(records)) {
        QMessageBox::warning(this, QStringLiteral("Audit log write failed"),
            QStringLiteral("The operation completed, but DataGuard could not persist the activity record to the application data directory."));
    }
    if (!certificateSaved) {
        QMessageBox::warning(this, QStringLiteral("PDF certificate generation failed"),
            QStringLiteral("The activity was recorded, but its PDF certificate could not be saved. Check write access to the DataGuard application-data folder."));
    }
}


QWidget* MainWindow::buildAssistantPage()
{
    auto* page = new QWidget;
    auto* pageLayout = new QVBoxLayout(page);
    pageLayout->setContentsMargins(4, 4, 8, 8);
    pageLayout->setSpacing(12);

    auto* intro = makeCard(page);
    auto* introLayout = new QVBoxLayout(intro);
    introLayout->setContentsMargins(18, 16, 18, 16);
    introLayout->setSpacing(7);
    introLayout->addWidget(heading(QStringLiteral("DataGuard Assistant"), intro));
    introLayout->addWidget(bodyText(
        QStringLiteral("Ask about the current device, scan, wipe method, recorded result, verification, or certificate. "
                       "This assistant explains the application's evidence; it cannot start a wipe or recovery."),
        intro));
    m_assistantStatus = bodyText(
        QStringLiteral("Local rule-based mode · no cloud connection required"), intro);
    m_assistantStatus->setStyleSheet(QStringLiteral("color:#75d8a0;font-size:12px;"));
    introLayout->addWidget(m_assistantStatus);
    pageLayout->addWidget(intro);

    auto* chat = makeCard(page);
    auto* chatLayout = new QVBoxLayout(chat);
    chatLayout->setContentsMargins(14, 12, 14, 14);
    chatLayout->setSpacing(9);
    auto* headingRow = new QHBoxLayout;
    headingRow->addWidget(heading(QStringLiteral("Conversation"), chat));
    headingRow->addStretch();
    m_assistantClearButton = new QPushButton(QStringLiteral("Clear conversation"), chat);
    m_assistantClearButton->setStyleSheet(QStringLiteral(
        "QPushButton{color:#dbe9f7;background:rgba(44,73,105,150);border:1px solid rgba(148,186,216,75);border-radius:7px;padding:7px 10px;}"));
    connect(m_assistantClearButton, &QPushButton::clicked,
            this, &MainWindow::clearAssistantConversation);
    headingRow->addWidget(m_assistantClearButton);
    chatLayout->addLayout(headingRow);

    m_assistantTranscript = new QTextBrowser(chat);
    m_assistantTranscript->setReadOnly(true);
    m_assistantTranscript->setOpenLinks(false);
    m_assistantTranscript->setMinimumHeight(245);
    m_assistantTranscript->setStyleSheet(QStringLiteral(
        "QTextBrowser{color:#eaf3ff;background:rgba(2,11,29,220);border:1px solid rgba(122,177,211,65);border-radius:9px;padding:9px;selection-background-color:#285577;}"));
    chatLayout->addWidget(m_assistantTranscript, 1);
    pageLayout->addWidget(chat, 1);

    auto* prompts = makeCard(page);
    auto* promptsLayout = new QVBoxLayout(prompts);
    promptsLayout->setContentsMargins(14, 12, 14, 12);
    promptsLayout->setSpacing(8);
    promptsLayout->addWidget(heading(QStringLiteral("Suggested questions"), prompts));
    m_assistantSuggestionsLayout = new QGridLayout;
    m_assistantSuggestionsLayout->setHorizontalSpacing(8);
    m_assistantSuggestionsLayout->setVerticalSpacing(8);
    const QStringList suggested = {
        QStringLiteral("What does this scan mean?"),
        QStringLiteral("Why did the wipe fail?"),
        QStringLiteral("Explain the latest ML results"),
        QStringLiteral("What does my certificate prove?")
    };
    for (int i = 0; i < suggested.size(); ++i) {
        auto* button = new QPushButton(suggested.at(i), prompts);
        button->setCursor(Qt::PointingHandCursor);
        button->setMinimumHeight(35);
        button->setStyleSheet(QStringLiteral(
            "QPushButton{color:#eaf5ff;background:rgba(20,47,75,190);border:1px solid rgba(112,175,213,75);border-radius:8px;padding:7px 10px;text-align:left;} "
            "QPushButton:hover{background:rgba(29,83,119,220);} QPushButton:disabled{color:#8498ab;}"));
        connect(button, &QPushButton::clicked, this, [this, button]() {
            // Send is normally disabled while the input is empty, so don't
            // use its enabled state as a prerequisite for clicking a prompt.
            if (m_assistantInput &&
                (!m_assistantProcess || m_assistantProcess->state() == QProcess::NotRunning)) {
                m_assistantInput->setText(button->text());
                sendAssistantQuestion();
            }
        });
        m_assistantSuggestionButtons.push_back(button);
        m_assistantSuggestionsLayout->addWidget(button, i / 2, i % 2);
    }
    promptsLayout->addLayout(m_assistantSuggestionsLayout);
    pageLayout->addWidget(prompts);

    auto* navigation = makeCard(page);
    auto* navigationLayout = new QVBoxLayout(navigation);
    navigationLayout->setContentsMargins(14, 10, 14, 12);
    navigationLayout->setSpacing(6);
    navigationLayout->addWidget(bodyText(QStringLiteral("Suggested next screen"), navigation));
    m_assistantNavigationLayout = new QHBoxLayout;
    m_assistantNavigationLayout->setSpacing(8);
    navigationLayout->addLayout(m_assistantNavigationLayout);
    pageLayout->addWidget(navigation);

    auto* inputCard = makeCard(page);
    auto* inputLayout = new QHBoxLayout(inputCard);
    inputLayout->setContentsMargins(12, 10, 12, 10);
    inputLayout->setSpacing(8);
    m_assistantInput = new QLineEdit(inputCard);
    m_assistantInput->setMaxLength(2000);
    m_assistantInput->setPlaceholderText(QStringLiteral("Ask DataGuard a question…"));
    m_assistantInput->setClearButtonEnabled(true);
    m_assistantInput->setStyleSheet(QStringLiteral(
        "QLineEdit{color:#f2f7ff;background:rgba(2,11,29,220);border:1px solid rgba(122,177,211,80);border-radius:8px;padding:10px 12px;} "
        "QLineEdit:focus{border:1px solid #65d9f7;}"));
    inputLayout->addWidget(m_assistantInput, 1);
    m_assistantSendButton = new QPushButton(QStringLiteral("Send"), inputCard);
    stylePrimaryButton(m_assistantSendButton);
    m_assistantSendButton->setMinimumWidth(90);
    inputLayout->addWidget(m_assistantSendButton);
    connect(m_assistantSendButton, &QPushButton::clicked,
            this, &MainWindow::sendAssistantQuestion);
    connect(m_assistantInput, &QLineEdit::returnPressed,
            this, &MainWindow::sendAssistantQuestion);
    connect(m_assistantInput, &QLineEdit::textChanged, this, [this](const QString& text) {
        if (m_assistantSendButton &&
            (!m_assistantProcess || m_assistantProcess->state() == QProcess::NotRunning))
            m_assistantSendButton->setEnabled(!text.trimmed().isEmpty());
    });
    pageLayout->addWidget(inputCard);

    m_assistantTimeoutTimer = new QTimer(this);
    m_assistantTimeoutTimer->setSingleShot(true);
    connect(m_assistantTimeoutTimer, &QTimer::timeout, this, [this]() {
        if (m_assistantProcess && m_assistantProcess->state() != QProcess::NotRunning) {
            m_assistantTimedOut = true;
            m_assistantProcess->kill();
        }
    });

    appendAssistantMessage(QStringLiteral("assistant"),
        QStringLiteral("Hello! I can explain current application details and guide you to the relevant screen. "
                       "I will say when information is missing rather than inventing device state or ML results."));
    return scrollPage(page);
}

QJsonObject MainWindow::buildAssistantContext()
{
    QJsonObject context;
    const QStringList screenNames = {
        QStringLiteral("dashboard"), QStringLiteral("devices"),
        QStringLiteral("scan_results"), QStringLiteral("operations"),
        QStringLiteral("activity_log"), QStringLiteral("certificates"),
        QStringLiteral("assistant"), QStringLiteral("settings")
    };
    int screenIndex = m_pages ? m_pages->currentIndex() : 0;
    if (screenIndex == 6) screenIndex = m_lastNonAssistantPageIndex;
    if (screenIndex < 0 || screenIndex >= screenNames.size()) screenIndex = 0;
    context.insert(QStringLiteral("screen"), screenNames.at(screenIndex));
    if (!m_signedInUser.trimmed().isEmpty())
        context.insert(QStringLiteral("signed_in_user"), m_signedInUser.trimmed().left(120));
    char selectedDriveLetter = 0;

    // Read-only device summary. Do not expose raw physical paths or serial numbers.
    if (driveList && driveList->currentRow() >= 0) {
        DeviceManager manager;
        const auto drives = manager.listRemovableDrives();
        const int row = driveList->currentRow();
        if (row < static_cast<int>(drives.size())) {
            const auto& drive = drives.at(static_cast<size_t>(row));
            selectedDriveLetter = drive.letter;
            QJsonObject device;
            device.insert(QStringLiteral("display_name"),
                QStringLiteral("USB Drive %1:").arg(QChar(drive.letter)));
            const QString model = QString::fromStdString(drive.model).trimmed();
            if (!model.isEmpty()) device.insert(QStringLiteral("model"), model.left(120));
            device.insert(QStringLiteral("drive_letter"), QStringLiteral("%1:").arg(QChar(drive.letter)));
            device.insert(QStringLiteral("capacity_bytes"), static_cast<double>(drive.sizeBytes));
            device.insert(QStringLiteral("connected"), true);
            context.insert(QStringLiteral("device"), device);
        }
    }

    DeviceManager inventoryManager;
    const auto allDrives = inventoryManager.listRemovableDrives();
    QJsonArray deviceInventory;
    for (size_t i = 0; i < allDrives.size() && deviceInventory.size() < 8; ++i) {
        const auto& drive = allDrives[i];
        QJsonObject item;
        item.insert(QStringLiteral("display_name"),
            QStringLiteral("USB Drive %1:").arg(QChar(drive.letter)));
        const QString model = QString::fromStdString(drive.model).trimmed();
        if (!model.isEmpty()) item.insert(QStringLiteral("model"), model.left(100));
        item.insert(QStringLiteral("drive_letter"), QStringLiteral("%1:").arg(QChar(drive.letter)));
        item.insert(QStringLiteral("capacity_bytes"), static_cast<double>(drive.sizeBytes));
        item.insert(QStringLiteral("connected"), true);
        item.insert(QStringLiteral("selected"), drive.letter == selectedDriveLetter);
        deviceInventory.append(item);
    }
    if (!deviceInventory.isEmpty())
        context.insert(QStringLiteral("devices"), deviceInventory);

    // A scan is current only if the selected physical device is the one scanned.
    const bool scanMatchesSelectedDevice =
        selectedDriveLetter != 0 &&
        m_assistantScannedDriveLetter == selectedDriveLetter;
    if (scanMatchesSelectedDevice && fileTree && scanStatusLabel &&
        fileTree->topLevelItemCount() > 0 &&
        scanStatusLabel->text().startsWith(QStringLiteral("Scan complete"))) {
        int existingCount = 0, deletedCount = 0, hiddenCount = 0;
        std::function<void(QTreeWidgetItem*)> visit;
        visit = [&](QTreeWidgetItem* item) {
            if (!item) return;
            const QString status = item->text(2);
            if (status == QStringLiteral("Existing")) ++existingCount;
            else if (status == QStringLiteral("DELETED")) ++deletedCount;
            else if (status.compare(QStringLiteral("Hidden"), Qt::CaseInsensitive) == 0) ++hiddenCount;
            for (int i = 0; i < item->childCount(); ++i) visit(item->child(i));
        };
        for (int i = 0; i < fileTree->topLevelItemCount(); ++i) visit(fileTree->topLevelItem(i));

        QJsonObject scan;
        scan.insert(QStringLiteral("existing_entries"), existingCount);
        scan.insert(QStringLiteral("potentially_deleted_entries"), deletedCount);
        if (hiddenCount > 0) scan.insert(QStringLiteral("hidden_entries"), hiddenCount);
        scan.insert(QStringLiteral("scan_status"), QStringLiteral("completed"));
        QJsonArray limitations;
        limitations.append(QStringLiteral("Deleted entries do not guarantee recoverable file contents."));
        for (const auto& entry : deletedFileEntries) {
            if (entry.second.sizeBytes > 0 && entry.second.extents.empty()) {
                limitations.append(QStringLiteral("At least one listed deleted entry has no physical extents available."));
                break;
            }
        }
        scan.insert(QStringLiteral("limitations"), limitations);
        context.insert(QStringLiteral("scan_summary"), scan);

        QJsonArray scanEntries;
        const QString driveRoot = QStringLiteral("Drive %1:").arg(QChar(selectedDriveLetter));
        std::function<void(QTreeWidgetItem*, const QString&)> collectScanEntries;
        collectScanEntries = [&](QTreeWidgetItem* node, const QString& parentLocation) {
            if (!node || scanEntries.size() >= 12) return;
            const QString name = node->text(0).trimmed();
            const QString itemStatus = node->text(2).trimmed();
            QString location = parentLocation;
            if (itemStatus == QStringLiteral("Drive Root")) {
                location = driveRoot;
            } else if (itemStatus == QStringLiteral("Recovered")) {
                location = parentLocation + QStringLiteral(" > Deleted Files");
            } else if (!name.isEmpty()) {
                location = parentLocation.isEmpty() ? name
                    : parentLocation + QStringLiteral(" > ") + name;
            }

            if (!name.isEmpty() &&
                itemStatus != QStringLiteral("Drive Root") &&
                itemStatus != QStringLiteral("Recovered") &&
                scanEntries.size() < 12) {
                QJsonObject entry;
                entry.insert(QStringLiteral("file_name"), name.left(120));
                entry.insert(QStringLiteral("location"), location.left(180));
                entry.insert(QStringLiteral("status"), itemStatus.left(40));
                const QString sizeDisplay = node->text(1).trimmed();
                if (!sizeDisplay.isEmpty())
                    entry.insert(QStringLiteral("size_display"), sizeDisplay.left(30));
                const QString modified = node->text(3).trimmed();
                if (!modified.isEmpty() && modified != QStringLiteral("—"))
                    entry.insert(QStringLiteral("modified"), modified.left(60));
                if (itemStatus == QStringLiteral("DELETED"))
                    entry.insert(QStringLiteral("is_deleted"), true);
                scanEntries.append(entry);
            }
            for (int child = 0; child < node->childCount() && scanEntries.size() < 12; ++child)
                collectScanEntries(node->child(child), location);
        };
        for (int top = 0; top < fileTree->topLevelItemCount() && scanEntries.size() < 12; ++top)
            collectScanEntries(fileTree->topLevelItem(top), QString());
        if (!scanEntries.isEmpty())
            context.insert(QStringLiteral("scan_entries"), scanEntries);
    }

    std::vector<FileToWipe> selected;
    if (scanMatchesSelectedDevice && fileTree)
        collectSelectedFiles(fileTree->invisibleRootItem(), selected);
    QJsonObject selectedOperation;
    if (wipeMethodCombo) selectedOperation.insert(QStringLiteral("wipe_method"), wipeMethodCombo->currentText());
    if (!scanMatchesSelectedDevice && screenIndex == 3) {
        selectedOperation.insert(QStringLiteral("workflow"),
            QStringLiteral("current_drive_scan_required_before_target_context"));
        context.insert(QStringLiteral("selected_operation"), selectedOperation);
    } else if (!selected.empty()) {
        selectedOperation.insert(QStringLiteral("workflow"), QStringLiteral("selected_file_wipe"));
        selectedOperation.insert(QStringLiteral("selected_file_count"), static_cast<int>(selected.size()));
        QJsonArray selectedFiles;
        const size_t selectedCount = std::min<size_t>(selected.size(), 5);
        for (size_t i = 0; i < selectedCount; ++i) {
            QJsonObject item;
            item.insert(QStringLiteral("file_name"), QString::fromStdString(selected[i].name).left(120));
            item.insert(QStringLiteral("is_deleted"), selected[i].isDeleted);
            item.insert(QStringLiteral("size_bytes"), static_cast<double>(selected[i].sizeBytes));
            selectedFiles.append(item);
        }
        selectedOperation.insert(QStringLiteral("selected_files"), selectedFiles);
        context.insert(QStringLiteral("selected_operation"), selectedOperation);
    } else if (screenIndex == 3) {
        selectedOperation.insert(QStringLiteral("workflow"), QStringLiteral("full_drive_wipe_confirmation_required"));
        context.insert(QStringLiteral("selected_operation"), selectedOperation);
    }

    const QJsonArray records = readAuditRecords();
    QJsonArray activityHistory;
    QJsonArray certificateHistory;

    auto activityContext = [this](const QJsonObject& record) {
        QJsonObject item;
        item.insert(QStringLiteral("timestamp"), displayTimestamp(record));
        item.insert(QStringLiteral("user"), record.value(QStringLiteral("user")).toString().left(80));
        item.insert(QStringLiteral("file_name"), record.value(QStringLiteral("fileName")).toString().left(120));
        item.insert(QStringLiteral("location"), conciseLocation(record).left(180));
        item.insert(QStringLiteral("method"), readableMethod(record));
        item.insert(QStringLiteral("status"), record.value(QStringLiteral("status")).toString());
        item.insert(QStringLiteral("outcome"), readableOutcome(record));
        item.insert(QStringLiteral("verification"), readableVerification(record));
        item.insert(QStringLiteral("ml_summary"), mlTableSummary(record).left(160));
        item.insert(QStringLiteral("error_message"), record.value(QStringLiteral("errorMessage")).toString().left(100));
        item.insert(QStringLiteral("certificate_id"), record.value(QStringLiteral("certificateId")).toString().left(100));
        bool passOk = false;
        const int passes = record.value(QStringLiteral("passes")).toString().toInt(&passOk);
        if (passOk) item.insert(QStringLiteral("passes"), passes);
        const QString pdfPath = record.value(QStringLiteral("certificatePath")).toString();
        item.insert(QStringLiteral("certificate_available"),
            !pdfPath.isEmpty() && QFileInfo(pdfPath).exists() && QFileInfo(pdfPath).size() > 0);
        return item;
    };

    // Newest records first. This gives the assistant an audit-history window,
    // instead of requiring the user to manually restate the last operation.
    for (int i = records.size() - 1; i >= 0 && activityHistory.size() < 8; --i) {
        if (!records.at(i).isObject()) continue;
        const QJsonObject record = records.at(i).toObject();
        activityHistory.append(activityContext(record));

        const QString certificateId = record.value(QStringLiteral("certificateId")).toString().trimmed();
        if (!certificateId.isEmpty() && certificateHistory.size() < 5) {
            QJsonObject certificate = activityContext(record);
            certificate.insert(QStringLiteral("pdf_ready"),
                certificate.value(QStringLiteral("certificate_available")).toBool());
            certificateHistory.append(certificate);
        }
    }
    if (!activityHistory.isEmpty()) {
        context.insert(QStringLiteral("activity_records"), activityHistory);
        // The first activity record is the newest actual audit record.
        context.insert(QStringLiteral("last_recorded_operation"), activityHistory.first().toObject());
    }
    if (!certificateHistory.isEmpty())
        context.insert(QStringLiteral("certificate_records"), certificateHistory);

    QString selectedCertificateId;
    if (screenIndex == 5 && m_certificatesTable &&
        m_certificatesTable->currentRow() >= 0 &&
        m_certificatesTable->item(m_certificatesTable->currentRow(), 0)) {
        selectedCertificateId = m_certificatesTable->item(m_certificatesTable->currentRow(), 0)->text();
    } else if (screenIndex == 4 && m_activityTable &&
               m_activityTable->currentRow() >= 0 &&
               m_activityTable->item(m_activityTable->currentRow(), 7)) {
        selectedCertificateId = m_activityTable->item(m_activityTable->currentRow(), 7)->text();
    }
    if (!selectedCertificateId.isEmpty()) {
        for (int i = records.size() - 1; i >= 0; --i) {
            if (!records.at(i).isObject()) continue;
            const QJsonObject record = records.at(i).toObject();
            if (record.value(QStringLiteral("certificateId")).toString() != selectedCertificateId) continue;
            QJsonObject certificate;
            certificate.insert(QStringLiteral("certificate_id"), selectedCertificateId);
            certificate.insert(QStringLiteral("timestamp"), record.value(QStringLiteral("timestamp")).toString());
            certificate.insert(QStringLiteral("user"), record.value(QStringLiteral("user")).toString());
            certificate.insert(QStringLiteral("file_name"), record.value(QStringLiteral("fileName")).toString());
            certificate.insert(QStringLiteral("location"), conciseLocation(record));
            certificate.insert(QStringLiteral("method"), readableMethod(record));
            certificate.insert(QStringLiteral("status"), record.value(QStringLiteral("status")).toString());
            certificate.insert(QStringLiteral("outcome"), readableOutcome(record));
            certificate.insert(QStringLiteral("verification"), readableVerification(record));
            certificate.insert(QStringLiteral("ml_summary"), mlTableSummary(record).left(160));
            const QString pdfPath = record.value(QStringLiteral("certificatePath")).toString();
            certificate.insert(QStringLiteral("pdf_ready"),
                !pdfPath.isEmpty() && QFileInfo(pdfPath).exists() && QFileInfo(pdfPath).size() > 0);
            bool passesOk = false;
            const int passes = record.value(QStringLiteral("passes")).toString().toInt(&passesOk);
            if (passesOk) certificate.insert(QStringLiteral("passes"), passes);
            context.insert(QStringLiteral("certificate"), certificate);
            break;
        }
    }
    return context;
}

void MainWindow::appendAssistantMessage(const QString& role, const QString& text)
{
    if (!m_assistantTranscript) return;
    const bool user = role == QStringLiteral("user");
    const QString title = user ? QStringLiteral("You") : QStringLiteral("DataGuard Assistant");
    const QString safe = text.toHtmlEscaped().replace(QStringLiteral("\n"), QStringLiteral("<br>"));
    const QString html = QStringLiteral(
        "<div style='margin:8px 0 14px 0;padding:10px 12px;background:%1;border-radius:9px;color:#eff6ff;'>"
        "<div style='font-weight:700;color:%2;margin-bottom:5px;'>%3</div><div style='line-height:1.45;'>%4</div></div>")
        .arg(user ? QStringLiteral("rgba(24,73,104,0.48)") : QStringLiteral("rgba(23,34,53,0.80)"),
             user ? QStringLiteral("#78d7f3") : QStringLiteral("#d9e9ff"),
             title.toHtmlEscaped(), safe);
    m_assistantTranscript->append(html);
    m_assistantTranscript->verticalScrollBar()->setValue(m_assistantTranscript->verticalScrollBar()->maximum());
}

void MainWindow::setAssistantBusy(bool busy)
{
    if (m_assistantInput) m_assistantInput->setEnabled(!busy);
    if (m_assistantSendButton) {
        m_assistantSendButton->setEnabled(!busy && m_assistantInput &&
            !m_assistantInput->text().trimmed().isEmpty());
        m_assistantSendButton->setText(busy ? QStringLiteral("Thinking…") : QStringLiteral("Send"));
    }
    if (m_assistantClearButton) m_assistantClearButton->setEnabled(!busy);
    for (auto* button : m_assistantSuggestionButtons)
        if (button) button->setEnabled(!busy);
}

void MainWindow::clearAssistantConversation()
{
    if (m_assistantProcess && m_assistantProcess->state() != QProcess::NotRunning) return;
    if (m_assistantTranscript) m_assistantTranscript->clear();
    if (m_assistantNavigationLayout) {
        while (QLayoutItem* item = m_assistantNavigationLayout->takeAt(0)) {
            if (QWidget* widget = item->widget()) widget->deleteLater();
            delete item;
        }
    }
    m_assistantNavigationButtons.clear();
    appendAssistantMessage(QStringLiteral("assistant"),
        QStringLiteral("Conversation cleared. Ask about the current application state whenever you're ready."));
}

void MainWindow::addAssistantNavigationButtons(const QJsonArray& suggestions)
{
    if (!m_assistantNavigationLayout) return;
    while (QLayoutItem* item = m_assistantNavigationLayout->takeAt(0)) {
        if (QWidget* widget = item->widget()) widget->deleteLater();
        delete item;
    }
    m_assistantNavigationButtons.clear();

    const QMap<QString, int> destinations = {
        {QStringLiteral("dashboard"), 0}, {QStringLiteral("devices"), 1},
        {QStringLiteral("scan_results"), 2}, {QStringLiteral("operations"), 3},
        {QStringLiteral("activity_log"), 4}, {QStringLiteral("certificates"), 5},
        {QStringLiteral("assistant"), 6}, {QStringLiteral("settings"), 7}
    };
    const QStringList titles = {
        QStringLiteral("Dashboard"), QStringLiteral("Devices"),
        QStringLiteral("Scan Results"), QStringLiteral("Operations"),
        QStringLiteral("Activity Log"), QStringLiteral("Certificates"),
        QStringLiteral("Assistant"), QStringLiteral("Settings")
    };
    int count = 0;
    for (const QJsonValue& value : suggestions) {
        if (!value.isObject() || count >= 3) continue;
        const QJsonObject item = value.toObject();
        const QString destination = item.value(QStringLiteral("destination")).toString();
        const QString label = item.value(QStringLiteral("label")).toString().left(80);
        if (!destinations.contains(destination) || label.isEmpty()) continue;
        const int index = destinations.value(destination);
        auto* button = new QPushButton(label, m_assistantNavigationLayout->parentWidget());
        button->setCursor(Qt::PointingHandCursor);
        button->setStyleSheet(QStringLiteral(
            "QPushButton{color:#eaf5ff;background:rgba(20,47,75,190);border:1px solid rgba(112,175,213,75);border-radius:8px;padding:7px 10px;}"));
        connect(button, &QPushButton::clicked, this, [this, index, titles]() {
            if (index >= 0 && index < m_navigationButtons.size())
                m_navigationButtons[index]->setChecked(true);
            navigateTo(index, titles.at(index));
        });
        m_assistantNavigationButtons.push_back(button);
        m_assistantNavigationLayout->addWidget(button);
        ++count;
    }
    m_assistantNavigationLayout->addStretch();
}

void MainWindow::renderAssistantResponse(const QJsonObject& response)
{
    appendAssistantMessage(QStringLiteral("assistant"), response.value(QStringLiteral("answer")).toString());
    const QJsonArray caveats = response.value(QStringLiteral("caveats")).toArray();
    if (!caveats.isEmpty()) {
        QString text = QStringLiteral("Important");
        for (const QJsonValue& value : caveats) {
            if (value.isString() && !value.toString().trimmed().isEmpty())
                text += QStringLiteral("\n• ") + value.toString().trimmed();
        }
        appendAssistantMessage(QStringLiteral("assistant"), text);
    }
    addAssistantNavigationButtons(response.value(QStringLiteral("suggested_navigation")).toArray());
}

void MainWindow::handleAssistantUnavailable(const QString& reason)
{
    const QString q = m_assistantPendingQuestion.trimmed().toLower();
    QString answer;
    QJsonArray navigation;

    auto addNav = [&navigation](const QString& label, const QString& destination) {
        QJsonObject item;
        item.insert(QStringLiteral("label"), label);
        item.insert(QStringLiteral("destination"), destination);
        navigation.append(item);
    };

    if (q.contains(QStringLiteral("no physical extents")) || q.contains(QStringLiteral("extent"))) {
        answer = QStringLiteral("The scanner did not supply a trustworthy physical-extent list for this deleted entry. A visible deleted filename does not prove that the original storage locations are known. Do not continue with an inferred range on a drive containing important data.");
        addNav(QStringLiteral("Review Scan Results"), QStringLiteral("scan_results"));
    } else if (q.contains(QStringLiteral("wipe")) || q.contains(QStringLiteral("erase")) || q.contains(QStringLiteral("recover"))) {
        answer = QStringLiteral("I cannot start a wipe or recovery from chat. Use the normal application workflow, verify the physical target, and follow its confirmation prompts. Cancel if any target information is uncertain.");
        addNav(QStringLiteral("Open Operations"), QStringLiteral("operations"));
        addNav(QStringLiteral("Review Scan Results"), QStringLiteral("scan_results"));
    } else if (q.contains(QStringLiteral("certificate")) || q.contains(QStringLiteral("pdf"))) {
        answer = QStringLiteral("Open Certificates, select the relevant record, and open its PDF. The certificate records application-reported evidence; it is not a universal guarantee of permanent irrecoverability.");
        addNav(QStringLiteral("Open Certificates"), QStringLiteral("certificates"));
    } else if (q.contains(QStringLiteral("scan"))) {
        const QString status = scanStatusLabel ? scanStatusLabel->text() : QString();
        answer = status.startsWith(QStringLiteral("Scan complete"))
            ? QStringLiteral("The current UI reports: %1. This fallback does not independently inspect the device. Deleted entries are candidates, not proof that contents remain recoverable.").arg(status)
            : QStringLiteral("There is no completed scan summary in the current UI context. Open Devices, select the intended drive, and run a scan before asking again.");
        addNav(QStringLiteral("Open Devices"), QStringLiteral("devices"));
        addNav(QStringLiteral("Review Scan Results"), QStringLiteral("scan_results"));
    } else {
        answer = QStringLiteral("The local assistant service could not be reached (%1). Core device, scan and wipe workflows are separate and remain unaffected. Open the relevant screen for recorded application details.")
            .arg(reason.left(180));
        addNav(QStringLiteral("Open Devices"), QStringLiteral("devices"));
        addNav(QStringLiteral("Open Activity Log"), QStringLiteral("activity_log"));
    }

    appendAssistantMessage(QStringLiteral("assistant"), answer);
    addAssistantNavigationButtons(navigation);
    if (m_assistantStatus)
        m_assistantStatus->setText(QStringLiteral("Python assistant unavailable · built-in safe fallback is active"));
}

void MainWindow::sendAssistantQuestion()
{
    if (!m_assistantInput || !m_assistantSendButton ||
        (m_assistantProcess && m_assistantProcess->state() != QProcess::NotRunning))
        return;
    const QString question = m_assistantInput->text().trimmed();
    if (question.isEmpty()) return;
    if (question.size() > 2000) {
        QMessageBox::information(this, QStringLiteral("Question too long"),
            QStringLiteral("Please keep questions to 2,000 characters or fewer."));
        return;
    }

    m_assistantPendingQuestion = question;
    appendAssistantMessage(QStringLiteral("user"), question);
    m_assistantInput->clear();
    setAssistantBusy(true);
    if (m_assistantStatus)
        m_assistantStatus->setText(QStringLiteral("Preparing a private, minimal context snapshot…"));
    m_assistantStdout.clear();
    m_assistantTimedOut = false;

    const QString script = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("assistant/app/main.py"));
    if (!QFileInfo::exists(script)) {
        setAssistantBusy(false);
        handleAssistantUnavailable(QStringLiteral("the assistant script was not found beside the executable"));
        return;
    }

    QString interpreter = QStandardPaths::findExecutable(QStringLiteral("python.exe"));
    if (interpreter.isEmpty()) interpreter = QStandardPaths::findExecutable(QStringLiteral("python"));
    if (interpreter.isEmpty()) interpreter = QStandardPaths::findExecutable(QStringLiteral("python3.exe"));
    if (interpreter.isEmpty()) interpreter = QStandardPaths::findExecutable(QStringLiteral("python3"));
    QStringList arguments;
    if (interpreter.isEmpty()) {
        interpreter = QStandardPaths::findExecutable(QStringLiteral("py.exe"));
        if (interpreter.isEmpty()) interpreter = QStandardPaths::findExecutable(QStringLiteral("py"));
        if (!interpreter.isEmpty()) arguments << QStringLiteral("-3");
    }
    if (interpreter.isEmpty()) {
        setAssistantBusy(false);
        handleAssistantUnavailable(QStringLiteral("no Python interpreter was found"));
        return;
    }
    arguments << QFileInfo(script).absoluteFilePath();

    QJsonObject request;
    m_assistantPendingRequestId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    request.insert(QStringLiteral("request_id"), m_assistantPendingRequestId);
    request.insert(QStringLiteral("question"), question);
    request.insert(QStringLiteral("context"), buildAssistantContext());
    const QByteArray payload = QJsonDocument(request).toJson(QJsonDocument::Compact);

    auto* process = new QProcess(this);
    m_assistantProcess = process;
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("PYTHONUTF8"), QStringLiteral("1"));
    environment.insert(QStringLiteral("PYTHONDONTWRITEBYTECODE"), QStringLiteral("1"));
    process->setProcessEnvironment(environment);
    process->setWorkingDirectory(QFileInfo(script).absolutePath());

    connect(process, &QProcess::started, this, [this, process, payload]() {
        if (m_assistantProcess != process) return;
        process->write(payload);
        process->closeWriteChannel();
        if (m_assistantTimeoutTimer) m_assistantTimeoutTimer->start(8000);
        if (m_assistantStatus) m_assistantStatus->setText(QStringLiteral("Answering locally…"));
    });
    connect(process, &QProcess::readyReadStandardOutput, this, [this, process]() {
        if (m_assistantProcess != process) return;
        const QByteArray chunk = process->readAllStandardOutput();
        if (m_assistantStdout.size() + chunk.size() <= 64 * 1024)
            m_assistantStdout += chunk;
        else
            m_assistantStdout.clear();
    });
    connect(process, &QProcess::finished, this,
        [this, process](int exitCode, QProcess::ExitStatus exitStatus) {
            if (m_assistantProcess != process) return;
            if (m_assistantTimeoutTimer) m_assistantTimeoutTimer->stop();
            const QByteArray trailing = process->readAllStandardOutput();
            if (m_assistantStdout.size() + trailing.size() <= 64 * 1024)
                m_assistantStdout += trailing;
            m_assistantProcess = nullptr;
            process->deleteLater();
            setAssistantBusy(false);

            if (m_assistantTimedOut) {
                handleAssistantUnavailable(QStringLiteral("the local assistant timed out"));
                return;
            }
            if (exitStatus != QProcess::NormalExit || exitCode != 0) {
                handleAssistantUnavailable(QStringLiteral("the local assistant process exited unexpectedly"));
                return;
            }
            QJsonParseError parseError{};
            const QJsonDocument doc = QJsonDocument::fromJson(m_assistantStdout, &parseError);
            if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
                handleAssistantUnavailable(QStringLiteral("the assistant returned an invalid response"));
                return;
            }
            const QJsonObject response = doc.object();
            if (response.value(QStringLiteral("request_id")).toString() != m_assistantPendingRequestId ||
                !response.value(QStringLiteral("answer")).isString()) {
                handleAssistantUnavailable(QStringLiteral("the assistant response was incomplete"));
                return;
            }
            if (m_assistantStatus)
                m_assistantStatus->setText(QStringLiteral("Local rule-based mode · no cloud connection required"));
            renderAssistantResponse(response);
        });
    connect(process, &QProcess::errorOccurred, this,
        [this, process](QProcess::ProcessError error) {
            if (m_assistantProcess != process || error != QProcess::FailedToStart) return;
            if (m_assistantTimeoutTimer) m_assistantTimeoutTimer->stop();
            m_assistantProcess = nullptr;
            process->deleteLater();
            setAssistantBusy(false);
            handleAssistantUnavailable(QStringLiteral("Python could not be started"));
        });
    process->start(interpreter, arguments);
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
    m_assistantScannedDriveLetter = 0;
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
    m_assistantScannedDriveLetter = drive.letter;

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
            if (f.isDeleted) {
                f.fullPath = QStringLiteral("Drive %1: > Deleted Files > %2")
                    .arg(QChar(currentDriveLetter)).arg(child->text(0)).toStdString();
            } else {
                QStringList pathParts;
                QTreeWidgetItem* pathNode = child;
                while (pathNode) {
                    const QString part = pathNode->text(0).trimmed();
                    if (pathNode->text(2) == QStringLiteral("Drive Root")) break;
                    if (!part.isEmpty() && part != QStringLiteral("Deleted Files")) pathParts.prepend(part);
                    pathNode = pathNode->parent();
                }
                QString logicalPath = QStringLiteral("Drive %1:").arg(QChar(currentDriveLetter));
                if (!pathParts.isEmpty()) logicalPath += QStringLiteral(" > ") + pathParts.join(QStringLiteral(" > "));
                f.fullPath = logicalPath.toStdString();
            }
            if (f.isDeleted) {
                f.fullPath = QStringLiteral("Drive %1: > Deleted Files > %2")
                    .arg(QChar(currentDriveLetter)).arg(child->text(0)).toStdString();
            } else {
                QStringList pathParts;
                QTreeWidgetItem* pathNode = child;
                while (pathNode) {
                    const QString part = pathNode->text(0).trimmed();
                    if (pathNode->text(2) == QStringLiteral("Drive Root"))
                        break;
                    if (!part.isEmpty() && part != QStringLiteral("Deleted Files"))
                        pathParts.prepend(part);
                    pathNode = pathNode->parent();
                }
                QString logicalPath = QStringLiteral("Drive %1:").arg(QChar(currentDriveLetter));
                if (!pathParts.isEmpty())
                    logicalPath += QStringLiteral(" > ") + pathParts.join(QStringLiteral(" > "));
                f.fullPath = logicalPath.toStdString();
            }
            
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

    auto auditOperation = [this, &drive](const QString& fileName,
                                         const QString& filePath,
                                         const QString& source,
                                         const QString& methodName,
                                         int passes,
                                         bool success,
                                         const QString& verification,
                                         unsigned long long bytes,
                                         const QString& mlResults,
                                         const QString& error) {
        recordWipeActivity(fileName, filePath, source,
            QStringLiteral("%1:").arg(QChar(drive.letter)),
            QString::fromStdString(drive.path),
            QString::fromStdString(drive.model),
            methodName, passes, success, verification, bytes, mlResults, error);
    };

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

        auditOperation(QStringLiteral("Entire drive %1:").arg(QChar(drive.letter)),
            QStringLiteral("Drive %1: (entire drive)").arg(QChar(drive.letter)),
            QStringLiteral("Entire drive"), wipeMethodCombo->currentText(),
            passesForMethod(methodIndex), result.success,
            QStringLiteral("Separate verification is not reported by the original full-drive path"),
            result.bytesWiped,
            QStringLiteral("ML feature comparison is not run by the original full-drive path."),
            QString::fromStdString(result.errorMessage));
        refreshActivityLog();
        refreshCertificates();

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

        QStringList inferredFiles;
        for (const auto& selectedFile : selectedFiles) {
            if (selectedFile.isDeleted && selectedFile.fileEntry.extentMappingInferred)
                inferredFiles << QString::fromStdString(selectedFile.name);
        }
        if (!inferredFiles.isEmpty()) {
            const auto inferredReply = QMessageBox::warning(
                this,
                QStringLiteral("Confirm inferred deleted-file location"),
                QStringLiteral("The FAT32 allocation chain for the following deleted file(s) is no longer available:\n\n%1\n\nDataGuard found a contiguous range whose clusters are currently marked free in every FAT copy. This is a guarded best-effort mapping, but it cannot prove that the range contains only this file's old data; it may include contents from another deleted file.\n\nContinue with this inferred range?")
                    .arg(inferredFiles.join(QStringLiteral("\n"))),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (inferredReply != QMessageBox::Yes)
                return;
        }


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
        auditOperation(QString::fromStdString(file.name), auditPathForFile(file, drive.letter),
            QStringLiteral("Deleted Files"), wipeMethodCombo->currentText(),
            passesForMethod(methodIndex), false,
            QStringLiteral("Not performed — pre-wipe fingerprint read failed"), 0,
            QStringLiteral("ML analysis not generated because the original data could not be read."),
            QString::fromStdString(beforeRead.errorMessage));
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
        auditOperation(QString::fromStdString(file.name), auditPathForFile(file, drive.letter),
            QStringLiteral("Deleted Files"), wipeMethodCombo->currentText(),
            passesForMethod(methodIndex), false,
            QStringLiteral("Not performed — no physical extents were found"), 0,
            QStringLiteral("ML analysis not generated because no physical extent data was available."),
            QStringLiteral("The scanner did not provide wipeable physical extents for this entry."));
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
        auditOperation(QString::fromStdString(file.name), auditPathForFile(file, drive.letter),
            QStringLiteral("Deleted Files"), wipeMethodCombo->currentText(),
            passesForMethod(methodIndex), false,
            QStringLiteral("Wipe failed"), result.bytesWiped,
            QStringLiteral("ML analysis not generated because the wipe did not complete."),
            QString::fromStdString(result.errorMessage));
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

        auditOperation(QString::fromStdString(file.name), auditPathForFile(file, drive.letter),
            QStringLiteral("Deleted Files"), wipeMethodCombo->currentText(),
            passesForMethod(methodIndex), false,
            QStringLiteral("Verification failed — final-pass data did not match"),
            result.bytesWiped,
            QStringLiteral("ML analysis not generated because post-wipe verification failed."),
            QString::fromStdString(verificationResult.errorMessage));
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
    std::abs(before.dominantBytePercentage -
             afterFeatures.dominantBytePercentage);

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

    QStringList mlDetails;
    if (!afterRead.success) {
        mlDetails << QStringLiteral("ML analysis unavailable because the post-wipe data read failed.");
    } else if (similarityScoreFile == file.name) {
        mlDetails << QStringLiteral("Similarity score: %1%")
            .arg(similarityScore * 100.0, 0, 'f', 2);
        if (recoverabilityScoreGenerated) {
            mlDetails << QStringLiteral("Recoverability score: %1%")
                .arg(recoverabilityScore * 100.0, 0, 'f', 2);
            mlDetails << QStringLiteral("Recoverability risk: %1")
                .arg(riskLevel == 0 ? QStringLiteral("LOW") :
                     riskLevel == 1 ? QStringLiteral("MEDIUM") : QStringLiteral("HIGH"));
            if (!wipeRecommendation.empty())
                mlDetails << QStringLiteral("Recommendation: %1")
                    .arg(QString::fromStdString(wipeRecommendation));
        } else {
            mlDetails << QStringLiteral("Recoverability score: Not generated");
        }
    } else {
        mlDetails << QStringLiteral("ML analysis was not generated for this file.");
    }
    auditOperation(QString::fromStdString(file.name), auditPathForFile(file, drive.letter),
        QStringLiteral("Deleted Files"), wipeMethodCombo->currentText(),
        passesForMethod(methodIndex), true,
        QStringLiteral("PASSED — physical extents matched the expected final-pass data"),
        result.bytesWiped, mlDetails.join(QStringLiteral("\n")), QString());

} else {
    std::string filePath =
        std::string(1, currentDriveLetter) + ":\\" + file.name;

    QString qFilePath = QString::fromStdString(filePath);

    auto result = engine.wipeFile(qFilePath, method);

    auditOperation(QString::fromStdString(file.name), auditPathForFile(file, drive.letter),
        QStringLiteral("Existing Files"), wipeMethodCombo->currentText(),
        passesForMethod(methodIndex), result.success,
        QStringLiteral("Separate read-back verification is not reported by the original standard-file path"),
        result.bytesWiped,
        QStringLiteral("Before/after deleted-extent ML comparison is not run for standard existing-file wipes."),
        QString::fromStdString(result.errorMessage));

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

        refreshActivityLog();
        refreshCertificates();
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