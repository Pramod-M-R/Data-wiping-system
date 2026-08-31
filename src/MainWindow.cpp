#include "MainWindow.h"

#include "FeatureExtractor.h"
#include "SimilarityEvaluator.h"
#include "RecoverabilityEvaluator.h"
#include "DeviceManager.h"
#include "FileScanner.h"
#include "WipeEngine.h"

#include <QApplication>
#include <QCheckBox>
#include <QColor>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cmath>
#include <functional>
#include <string>
#include <vector>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    auto *central = new QWidget(this);
    auto *mainLayout = new QVBoxLayout(central);


    // =====================================================
    // TITLE
    // =====================================================

    statusLabel = new QLabel(
        "Secure Data Wipe Tool",
        this
    );

    statusLabel->setAlignment(Qt::AlignCenter);

    statusLabel->setStyleSheet(
        "font-size: 20px;"
        "font-weight: bold;"
        "padding: 10px;"
        "color: #00cfff;"
    );


    // =====================================================
    // DEVICE DETECTION
    // =====================================================

    auto *deviceGroup =
        new QGroupBox("Device Detection", this);

    auto *deviceLayout =
        new QVBoxLayout(deviceGroup);

    refreshButton =
        new QPushButton(
            "Detect USB Devices",
            this
        );

    driveList =
        new QListWidget(this);

    driveList->setMaximumHeight(100);

    deviceLayout->addWidget(refreshButton);
    deviceLayout->addWidget(driveList);


    // =====================================================
    // FILE SCANNER
    // =====================================================

    auto *scanGroup =
        new QGroupBox("File Scanner", this);

    auto *scanLayout =
        new QVBoxLayout(scanGroup);

    auto *scanTopLayout =
        new QHBoxLayout();

    scanButton =
        new QPushButton(
            "Scan Selected Drive",
            this
        );

    showDeletedCheck =
        new QCheckBox(
            "Show Deleted Files",
            this
        );

    showDeletedCheck->setChecked(true);

    scanTopLayout->addWidget(scanButton);
    scanTopLayout->addWidget(showDeletedCheck);
    scanTopLayout->addStretch();


    scanStatusLabel =
        new QLabel(
            "Select a drive and click Scan.",
            this
        );

    scanStatusLabel->setStyleSheet(
        "color: #aaaaaa;"
        "font-size: 12px;"
    );


    fileTree =
        new QTreeWidget(this);

    fileTree->setHeaderLabels(
        {
            "Name",
            "Size",
            "Status",
            "Modified"
        }
    );

    fileTree->header()->setSectionResizeMode(
        0,
        QHeaderView::Stretch
    );

    fileTree->setMinimumHeight(250);

    fileTree->setStyleSheet(
        "font-size: 12px;"
    );


    scanLayout->addLayout(scanTopLayout);
    scanLayout->addWidget(scanStatusLabel);
    scanLayout->addWidget(fileTree);


    // =====================================================
    // SECURE WIPE
    // =====================================================

    auto *wipeGroup =
        new QGroupBox(
            "Secure Wipe",
            this
        );

    auto *wipeLayout =
        new QVBoxLayout(wipeGroup);

    auto *methodLayout =
        new QHBoxLayout();

    auto *methodLabel =
        new QLabel(
            "Wipe Method:",
            this
        );


    wipeMethodCombo =
        new QComboBox(this);

    wipeMethodCombo->addItem(
        "Single Pass - Zeros",
        0
    );

    wipeMethodCombo->addItem(
        "DoD 3-Pass (Recommended)",
        1
    );

    wipeMethodCombo->addItem(
        "DoD 7-Pass (Maximum)",
        2
    );

    wipeMethodCombo->setStyleSheet(
        "padding: 5px;"
    );


    methodLayout->addWidget(methodLabel);
    methodLayout->addWidget(wipeMethodCombo);
    methodLayout->addStretch();


    wipeButton =
        new QPushButton(
            "START WIPE",
            this
        );

    wipeButton->setEnabled(false);

    wipeButton->setStyleSheet(
        "padding: 10px;"
        "font-size: 14px;"
        "font-weight: bold;"
        "background-color: #c0392b;"
        "color: white;"
        "border-radius: 4px;"
    );


    progressBar =
        new QProgressBar(this);

    progressBar->setRange(0, 100);
    progressBar->setValue(0);


    progressLabel =
        new QLabel(
            "Select a device and press START WIPE.",
            this
        );

    progressLabel->setAlignment(
        Qt::AlignCenter
    );

    progressLabel->setStyleSheet(
        "color: #aaaaaa;"
        "font-size: 12px;"
    );


    wipeLayout->addLayout(methodLayout);
    wipeLayout->addWidget(wipeButton);
    wipeLayout->addWidget(progressBar);
    wipeLayout->addWidget(progressLabel);


    // =====================================================
    // ML EVALUATION RESULTS
    // =====================================================

    mlEvaluationGroup =
        new QGroupBox(
            "ML Evaluation Results",
            this
        );

    auto *mlEvaluationLayout =
        new QVBoxLayout(
            mlEvaluationGroup
        );

    auto *mlFormLayout =
        new QFormLayout();


    similarityScoreLabel =
        new QLabel(
            "Similarity Score: 0.00%",
            this
        );

    similarityProgressBar =
        new QProgressBar(this);

    similarityProgressBar->setRange(
        0,
        100
    );

    similarityProgressBar->setValue(0);


    recoverabilityScoreLabel =
        new QLabel(
            "Recoverability Possibility: 0.00%",
            this
        );

    recoverabilityProgressBar =
        new QProgressBar(this);

    recoverabilityProgressBar->setRange(
        0,
        100
    );

    recoverabilityProgressBar->setValue(0);


    riskLevelLabel =
        new QLabel(
            "LOW",
            this
        );

    recommendedMethodLabel =
        new QLabel(
            "Not evaluated yet",
            this
        );

    recommendationLabel =
        new QLabel(
            "No evaluation yet.",
            this
        );

    recommendationLabel->setWordWrap(true);
    recommendationLabel->setMinimumHeight(50);


    mlFormLayout->addRow(
        "Similarity Score:",
        similarityScoreLabel
    );

    mlFormLayout->addRow(
        "Similarity Progress:",
        similarityProgressBar
    );

    mlFormLayout->addRow(
        "Recoverability Possibility:",
        recoverabilityScoreLabel
    );

    mlFormLayout->addRow(
        "Recoverability Progress:",
        recoverabilityProgressBar
    );

    mlFormLayout->addRow(
        "Risk Level:",
        riskLevelLabel
    );

    mlFormLayout->addRow(
        "Recommended Wipe Pass:",
        recommendedMethodLabel
    );

    mlFormLayout->addRow(
        "Recommendation:",
        recommendationLabel
    );


    mlEvaluationLayout->addLayout(
        mlFormLayout
    );


    // =====================================================
    // ASSEMBLE WINDOW
    // =====================================================

    mainLayout->addWidget(statusLabel);
    mainLayout->addWidget(deviceGroup);
    mainLayout->addWidget(scanGroup);
    mainLayout->addWidget(wipeGroup);
    mainLayout->addWidget(mlEvaluationGroup);

    mainLayout->setSpacing(10);

    mainLayout->setContentsMargins(
        15,
        15,
        15,
        15
    );


    setCentralWidget(central);

    setWindowTitle(
        "WipeEngine - Secure Data Erasure"
    );

    setMinimumSize(
        750,
        750
    );


    // =====================================================
    // SIGNAL CONNECTIONS
    // =====================================================

    connect(
        refreshButton,
        &QPushButton::clicked,
        this,
        &MainWindow::onRefreshClicked
    );

    connect(
        scanButton,
        &QPushButton::clicked,
        this,
        &MainWindow::onScanClicked
    );

    connect(
        wipeButton,
        &QPushButton::clicked,
        this,
        &MainWindow::onWipeClicked
    );

    connect(
        showDeletedCheck,
        &QCheckBox::toggled,
        this,
        &MainWindow::onToggleDeleted
    );

    connect(
        fileTree,
        &QTreeWidget::itemChanged,
        this,
        [this](
            QTreeWidgetItem *item,
            int column
        )
        {
            if (column == 0) {
                onFileChecked(
                    item,
                    column
                );
            }
        }
    );


    connect(
        driveList,
        &QListWidget::itemSelectionChanged,
        this,
        [this]()
        {
            bool selected =
                driveList->currentRow() >= 0;

            wipeButton->setEnabled(selected);
            scanButton->setEnabled(selected);
        }
    );
}

// =====================================================
// DETECT DRIVES
// =====================================================

void MainWindow::onRefreshClicked()
{
    driveList->clear();
    fileTree->clear();

    wipeButton->setEnabled(false);
    scanButton->setEnabled(false);

    statusLabel->setText(
        "Scanning ports..."
    );


    DeviceManager dm;

    auto drives =
        dm.listRemovableDrives();


    if (drives.empty()) {

        driveList->addItem(
            "No removable drives found."
        );

        statusLabel->setText(
            "No devices detected."
        );

        return;
    }


    for (auto &d : drives) {

        QString entry =
            QString("[%1:\\]  %2  |  %3 MB  |  %4")
                .arg(d.letter)
                .arg(
                    QString::fromStdString(
                        d.model
                    )
                )
                .arg(
                    d.sizeBytes /
                    (1024 * 1024)
                )
                .arg(
                    QString::fromStdString(
                        d.path
                    )
                );

        driveList->addItem(entry);
    }


    statusLabel->setText(
        QString(
            "%1 device(s) detected. Select one."
        ).arg(
            drives.size()
        )
    );
}


// =====================================================
// SCAN FILES
// =====================================================

void MainWindow::onScanClicked()
{
    int row =
        driveList->currentRow();

    if (row < 0)
        return;


    DeviceManager dm;

    auto drives =
        dm.listRemovableDrives();


    if (row >=
        static_cast<int>(drives.size())) {

        return;
    }


    auto &drive =
        drives[row];


    fileTree->clear();

    scanStatusLabel->setText(
        "Scanning... please wait."
    );

    QApplication::processEvents();


    std::string root =
        std::string(
            1,
            drive.letter
        ) + ":";


    // Store drive information for wiping.

    currentDriveLetter =
        drive.letter;

    currentDrivePath =
        drive.path;


    // =================================================
    // ROOT DRIVE NODE
    // =================================================

    auto *rootItem =
        new QTreeWidgetItem(
            fileTree
        );

    rootItem->setText(
        0,
        QString::fromStdString(
            root + "\\"
        )
    );

    rootItem->setText(
        2,
        "Drive Root"
    );

    rootItem->setForeground(
        0,
        QColor("#00cfff")
    );

    rootItem->setExpanded(true);


    // =================================================
    // RECURSIVE DIRECTORY TREE
    // =================================================

    std::function<
        void(
            const std::string &,
            QTreeWidgetItem *
        )
    > buildTree;


    buildTree =
        [&](const std::string &path,
            QTreeWidgetItem *parent)
    {
        std::string searchPath =
            path + "\\*";


        WIN32_FIND_DATAA fd;

        HANDLE hFind =
            FindFirstFileA(
                searchPath.c_str(),
                &fd
            );


        if (hFind ==
            INVALID_HANDLE_VALUE) {

            return;
        }


        do {

            std::string name =
                fd.cFileName;


            if (name == "." ||
                name == "..") {

                continue;
            }


            bool isDir =
                fd.dwFileAttributes &
                FILE_ATTRIBUTE_DIRECTORY;


            std::string fullPath =
                path + "\\" + name;


            auto *item =
                new QTreeWidgetItem(
                    parent
                );


            item->setText(
                0,
                QString::fromStdString(
                    name
                )
            );


            if (isDir) {

                item->setText(
                    1,
                    "—"
                );

                item->setText(
                    2,
                    "Folder"
                );

                item->setText(
                    3,
                    "—"
                );

                item->setForeground(
                    0,
                    QColor("#f0c040")
                );

                item->setExpanded(false);


                buildTree(
                    fullPath,
                    item
                );

            }
            else {

                ULARGE_INTEGER size;

                size.LowPart =
                    fd.nFileSizeLow;

                size.HighPart =
                    fd.nFileSizeHigh;


                item->setText(
                    1,
                    QString("%1 KB").arg(
                        size.QuadPart /
                        1024
                    )
                );

                item->setText(
                    2,
                    "Existing"
                );

                item->setText(
                    3,
                    "—"
                );

                item->setCheckState(
                    0,
                    Qt::Unchecked
                );
            }

        }
        while (
            FindNextFileA(
                hFind,
                &fd
            )
        );


        FindClose(hFind);
    };


    buildTree(
        root,
        rootItem
    );


    // =================================================
    // COUNT EXISTING FILES
    // =================================================

    int existingCount = 0;


    std::function<
        void(QTreeWidgetItem *)
    > countItems;


    countItems =
        [&](QTreeWidgetItem *item)
    {
        for (
            int i = 0;
            i < item->childCount();
            i++
        ) {

            auto *child =
                item->child(i);


            if (child->text(2) ==
                "Existing") {

                existingCount++;
            }


            countItems(child);
        }
    };


    countItems(rootItem);


    // =================================================
    // SCAN DELETED FILES
    // =================================================

    int deletedCount = 0;

    FileScanner scanner;


    std::string volumePath =
        "\\\\.\\" +
        std::string(
            1,
            drive.letter
        ) +
        ":";


    auto deleted =
        scanner.scanDeleted(
            volumePath
        );


    if (!deleted.empty()) {

        auto *deletedRoot =
            new QTreeWidgetItem(
                fileTree
            );


        deletedRoot->setText(
            0,
            "Deleted Files"
        );

        deletedRoot->setText(
            2,
            "Recovered"
        );

        deletedRoot->setForeground(
            0,
            QColor("#e74c3c")
        );

        deletedRoot->setExpanded(
            showDeletedCheck->isChecked()
        );

        deletedRoot->setHidden(
            !showDeletedCheck->isChecked()
        );


        for (auto &f : deleted) {

            auto *item =
                new QTreeWidgetItem(
                    deletedRoot
                );


            item->setText(
                0,
                QString::fromStdString(
                    f.name
                )
            );

            item->setText(
                1,
                QString("%1 KB").arg(
                    f.sizeBytes / 1024
                )
            );

            item->setText(
                2,
                "DELETED"
            );

            item->setText(
                3,
                QString::fromStdString(
                    f.lastModified
                )
            );


            // Physical location data.
            item->setData(
                0,
                Qt::UserRole,
                QVariant::fromValue<qulonglong>(
                    f.startCluster
                )
            );

            item->setData(
                1,
                Qt::UserRole,
                QVariant::fromValue<qulonglong>(
                    f.dataOffset
                )
            );

            item->setData(
                2,
                Qt::UserRole,
                QVariant::fromValue<qulonglong>(
                    f.clusterSize
                )
            );


            item->setCheckState(
                0,
                Qt::Unchecked
            );


            for (
                int col = 0;
                col < 4;
                col++
            ) {

                item->setForeground(
                    col,
                    QColor("#e74c3c")
                );
            }


            deletedCount++;
        }
    }


    scanStatusLabel->setText(
        QString(
            "Scan complete — %1 existing file(s), "
            "%2 deleted file(s) found."
        )
        .arg(existingCount)
        .arg(deletedCount)
    );
}


// =====================================================
// TOGGLE DELETED FILE VISIBILITY
// =====================================================

void MainWindow::onToggleDeleted(
    bool show
)
{
    for (
        int i = 0;
        i < fileTree->topLevelItemCount();
        i++
    ) {

        auto *item =
            fileTree->topLevelItem(i);


        if (item->text(2) ==
            "Recovered") {

            item->setHidden(!show);
            item->setExpanded(show);
        }
    }
}

// =====================================================
// FILE SELECTION HANDLING
// =====================================================

void MainWindow::onFileChecked(
    QTreeWidgetItem *item,
    int column
)
{
    Q_UNUSED(item);
    Q_UNUSED(column);

    std::vector<FileToWipe> selected;

    collectSelectedFiles(
        fileTree->invisibleRootItem(),
        selected
    );

    unsigned long long totalSize = 0;

    for (const auto &file : selected) {
        totalSize += file.sizeBytes;
    }


    if (selected.empty()) {

        progressLabel->setText(
            "Select files to wipe."
        );

    } else {

        progressLabel->setText(
            QString(
                "Selected: %1 file(s), %2 MB"
            )
            .arg(selected.size())
            .arg(
                totalSize /
                (1024 * 1024)
            )
        );
    }
}


// =====================================================
// COLLECT SELECTED FILES
// =====================================================

void MainWindow::collectSelectedFiles(
    QTreeWidgetItem *item,
    std::vector<FileToWipe> &selected
)
{
    if (!item)
        return;


    for (
        int i = 0;
        i < item->childCount();
        i++
    ) {

        auto *child =
            item->child(i);


        // Only collect checked actual files.
        if (
            child->checkState(0) == Qt::Checked &&
            child->text(2) != "Folder" &&
            child->text(2) != "Drive Root" &&
            child->text(0) != "Deleted Files"
        ) {

            FileToWipe file;


            file.name =
                child->text(0).toStdString();


            file.isDeleted =
                child->text(2) == "DELETED";


            file.isDirectory =
                child->text(2) == "Folder";


            // -------------------------------------------------
            // DELETED FILE PHYSICAL LOCATION
            // -------------------------------------------------

            if (file.isDeleted) {

                file.startCluster =
                    static_cast<uint32_t>(
                        child->data(
                            0,
                            Qt::UserRole
                        ).toULongLong()
                    );


                file.dataOffset =
                    child->data(
                        1,
                        Qt::UserRole
                    ).toULongLong();


                file.clusterSize =
                    child->data(
                        2,
                        Qt::UserRole
                    ).toULongLong();
            }


            // -------------------------------------------------
            // GET FILE SIZE
            // -------------------------------------------------

            QString sizeString =
                child->text(1);


            if (sizeString.contains("KB")) {

                file.sizeBytes =
                    sizeString
                    .split(" ")
                    .first()
                    .toULongLong()
                    * 1024;

            }
            else if (sizeString.contains("MB")) {

                file.sizeBytes =
                    sizeString
                    .split(" ")
                    .first()
                    .toULongLong()
                    * 1024
                    * 1024;

            }
            else {

                file.sizeBytes = 0;
            }


            selected.push_back(file);
        }


        // Recursively check folders and children.

        collectSelectedFiles(
            child,
            selected
        );
    }
}


// =====================================================
// SHOW ML EVALUATION
// =====================================================

void MainWindow::showMLEvaluation(
    double similarity,
    const RecoverabilityResult &result
)
{
    const double clampedSimilarity =
        std::max(
            0.0,
            std::min(
                100.0,
                similarity
            )
        );


    const double clampedRecoverability =
        std::max(
            0.0,
            std::min(
                100.0,
                result.recoverabilityPercentage
            )
        );


    // -------------------------------------------------
    // SIMILARITY SCORE
    // -------------------------------------------------

    similarityScoreLabel->setText(
        QString(
            "Similarity Score: %1%"
        )
        .arg(
            clampedSimilarity,
            0,
            'f',
            2
        )
    );


    similarityProgressBar->setValue(
        static_cast<int>(
            std::round(
                clampedSimilarity
            )
        )
    );


    // -------------------------------------------------
    // RECOVERABILITY SCORE
    // -------------------------------------------------

    recoverabilityScoreLabel->setText(
        QString(
            "Recoverability Possibility: %1%"
        )
        .arg(
            clampedRecoverability,
            0,
            'f',
            2
        )
    );


    recoverabilityProgressBar->setValue(
        static_cast<int>(
            std::round(
                clampedRecoverability
            )
        )
    );


    // -------------------------------------------------
    // RISK LEVEL
    // -------------------------------------------------

    QString riskText;


    switch (result.riskLevel) {

    case RiskLevel::LOW:

        riskText = "LOW";
        break;


    case RiskLevel::MEDIUM:

        riskText = "MEDIUM";
        break;


    case RiskLevel::HIGH:

        riskText = "HIGH";
        break;
    }


    riskLevelLabel->setText(
        riskText
    );


    // -------------------------------------------------
    // RECOMMENDED WIPE METHOD
    // -------------------------------------------------

    QString methodText;


    switch (
        result.recommendedMethod
    ) {

    case WipeMethod::ZEROS:

        methodText =
            "Single Pass - Zeros";
        break;


    case WipeMethod::DOD_3PASS:

        methodText =
            "DoD 3-Pass";
        break;


    case WipeMethod::DOD_7PASS:

        methodText =
            "DoD 7-Pass";
        break;


    case WipeMethod::RANDOM:

        methodText =
            "Random Fill";
        break;
    }


    recommendedMethodLabel->setText(
        methodText
    );


    // -------------------------------------------------
    // FINAL RECOMMENDATION
    // -------------------------------------------------

    recommendationLabel->setText(
        QString::fromStdString(
            result.recommendation
        )
    );
}

// =====================================================
// WIPE SELECTED FILES
// =====================================================

void MainWindow::onWipeClicked()
{
    int row = driveList->currentRow();

    if (row < 0)
        return;


    DeviceManager dm;

    auto drives =
        dm.listRemovableDrives();


    if (row >=
        static_cast<int>(drives.size())) {

        return;
    }


    auto &drive = drives[row];


    // =================================================
    // COLLECT SELECTED FILES
    // =================================================

    std::vector<FileToWipe> selectedFiles;

    collectSelectedFiles(
        fileTree->invisibleRootItem(),
        selectedFiles
    );


    // =================================================
    // NO FILE SELECTED
    // =================================================

    if (selectedFiles.empty()) {

        QMessageBox::information(
            this,
            "No File Selected",
            "Please select a file before starting the wipe."
        );

        return;
    }


    // =================================================
    // CONFIRM WIPE
    // =================================================

    unsigned long long totalSize = 0;

    for (const auto &file : selectedFiles) {
        totalSize += file.sizeBytes;
    }


    auto reply =
        QMessageBox::warning(
            this,
            "CONFIRM FILE WIPE",

            QString(
                "You are about to securely wipe:\n\n"
                "%1 file(s) (%2 MB)\n\n"
                "ALL DATA WILL BE PERMANENTLY DESTROYED.\n"
                "This cannot be undone.\n\n"
                "Are you absolutely sure?"
            )
            .arg(selectedFiles.size())
            .arg(
                totalSize /
                (1024 * 1024)
            ),

            QMessageBox::Yes |
            QMessageBox::No,

            QMessageBox::No
        );


    if (reply != QMessageBox::Yes)
        return;


    wipeButton->setEnabled(false);
    refreshButton->setEnabled(false);

    progressBar->setValue(0);


    // =================================================
    // SELECT WIPE METHOD
    // =================================================

    int methodIndex =
        wipeMethodCombo->currentIndex();


    WipeMethod method =
        (methodIndex == 0)
            ? WipeMethod::ZEROS
            : (methodIndex == 1)
                ? WipeMethod::DOD_3PASS
                : WipeMethod::DOD_7PASS;


    WipeEngine engine;

    unsigned long long wipedSize = 0;


    // =================================================
    // PROCESS EACH SELECTED FILE
    // =================================================

    for (
        size_t i = 0;
        i < selectedFiles.size();
        i++
    ) {

        auto &file =
            selectedFiles[i];


        progressLabel->setText(
            QString(
                "Wiping file %1 of %2: %3"
            )
            .arg(i + 1)
            .arg(selectedFiles.size())
            .arg(
                QString::fromStdString(
                    file.name
                )
            )
        );

        QApplication::processEvents();


        // =============================================
        // EXISTING FILE
        // =============================================

        if (!file.isDeleted) {

            std::string filePath =
                std::string(
                    1,
                    currentDriveLetter
                ) +
                ":\\" +
                file.name;


            QString qFilePath =
                QString::fromStdString(
                    filePath
                );


            // -----------------------------------------
            // CREATE FINGERPRINT BEFORE WIPE
            // -----------------------------------------

            FeatureExtractor extractor;

            FileFingerprint beforeFingerprint =
                extractor.extractFeatures(
                    qFilePath
                );


            // -----------------------------------------
            // WIPE FILE
            // -----------------------------------------

            auto result =
                engine.wipeFile(
                    qFilePath,
                    method
                );


            if (!result.success) {

                QMessageBox::warning(
                    this,
                    "Wipe Failed",

                    QString(
                        "Failed to wipe:\n%1\n\n"
                        "Reason: %2"
                    )
                    .arg(qFilePath)
                    .arg(
                        QString::fromStdString(
                            result.errorMessage
                        )
                    )
                );

                continue;
            }


            // -----------------------------------------
            // CREATE FINGERPRINT AFTER WIPE
            // -----------------------------------------

            FileFingerprint afterFingerprint =
                extractor.extractFeatures(
                    qFilePath
                );


            // -----------------------------------------
            // CALCULATE SIMILARITY
            // -----------------------------------------

            SimilarityEvaluator
                similarityEvaluator;


            double similarityScore =
                similarityEvaluator
                .calculateSimilarity(
                    beforeFingerprint,
                    afterFingerprint
                );


            // -----------------------------------------
            // CALCULATE RECOVERABILITY
            // -----------------------------------------

            RecoverabilityEvaluator
                recoverabilityEvaluator;


            RecoverabilityResult
                recoverabilityResult =
                    recoverabilityEvaluator
                    .evaluate(
                        beforeFingerprint,
                        afterFingerprint,
                        similarityScore
                    );


            // -----------------------------------------
            // DISPLAY ML RESULTS
            // -----------------------------------------

            showMLEvaluation(
                similarityScore,
                recoverabilityResult
            );


            wipedSize +=
                result.bytesWiped;


            // -----------------------------------------
            // REMOVE FILE AFTER WIPE
            // -----------------------------------------

            if (!QFile::remove(qFilePath)) {

                QMessageBox::warning(
                    this,
                    "File Deletion Warning",

                    QString(
                        "Wipe succeeded but the "
                        "file could not be deleted:\n%1"
                    )
                    .arg(qFilePath)
                );
            }
        }


        // =============================================
        // DELETED FILE
        // =============================================

        else {

            QMessageBox::information(
                this,
                "Deleted File",

                QString(
                    "Deleted file selected:\n\n%1\n\n"
                    "The deleted-file scanning information "
                    "has been detected successfully.\n\n"
                    "Raw cluster wiping and ML evaluation "
                    "will require the corresponding "
                    "wipeRawRegion implementation in "
                    "WipeEngine."
                )
                .arg(
                    QString::fromStdString(
                        file.name
                    )
                )
            );
        }


        // Update overall progress.

        int overallProgress =
            static_cast<int>(
                ((i + 1) * 100) /
                selectedFiles.size()
            );


        progressBar->setValue(
            overallProgress
        );

        QApplication::processEvents();
    }


    // =================================================
    // FINISH
    // =================================================

    wipeButton->setEnabled(true);
    refreshButton->setEnabled(true);

    progressBar->setValue(100);

    progressLabel->setText(
        "File wipe complete!"
    );


    QMessageBox::information(
        this,
        "Done",

        QString(
            "Wipe process completed.\n"
            "%1 file(s) processed.\n"
            "%2 MB wiped."
        )
        .arg(selectedFiles.size())
        .arg(
            wipedSize /
            (1024 * 1024)
        )
    );
}