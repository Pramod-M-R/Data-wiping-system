#pragma once

#include <QMainWindow>
#include <QListWidget>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QComboBox>
#include <QTreeWidget>
#include <QCheckBox>
#include <QGroupBox>

#include <vector>
#include <string>
#include <cstdint>

#include "RecoverabilityEvaluator.h"


// =====================================================
// FILE INFORMATION USED FOR WIPING
// =====================================================

struct FileToWipe
{
    std::string name;
    std::string fullPath;

    unsigned long long sizeBytes = 0;

    bool isDeleted = false;
    bool isDirectory = false;


    // Physical information for deleted files.

    uint32_t startCluster = 0;

    uint64_t dataOffset = 0;

    uint64_t clusterSize = 0;
};


// =====================================================
// MAIN WINDOW
// =====================================================

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:

    explicit MainWindow(
        QWidget *parent = nullptr
    );


private slots:

    void onRefreshClicked();

    void onScanClicked();

    void onWipeClicked();

    void onToggleDeleted(
        bool show
    );

    void onFileChecked(
        QTreeWidgetItem *item,
        int column
    );


private:

    // ================================================
    // FILE SELECTION
    // ================================================

    void collectSelectedFiles(
        QTreeWidgetItem *item,
        std::vector<FileToWipe> &selected
    );


    // ================================================
    // ML EVALUATION GUI
    // ================================================

    void showMLEvaluation(
        double similarity,
        const RecoverabilityResult &result
    );


    // ================================================
    // DEVICE SECTION
    // ================================================

    QListWidget *driveList = nullptr;

    QPushButton *refreshButton = nullptr;

    QLabel *statusLabel = nullptr;


    // ================================================
    // FILE SCANNER SECTION
    // ================================================

    QTreeWidget *fileTree = nullptr;

    QPushButton *scanButton = nullptr;

    QCheckBox *showDeletedCheck = nullptr;

    QLabel *scanStatusLabel = nullptr;


    // ================================================
    // WIPE SECTION
    // ================================================

    QComboBox *wipeMethodCombo = nullptr;

    QPushButton *wipeButton = nullptr;

    QProgressBar *progressBar = nullptr;

    QLabel *progressLabel = nullptr;


    // ================================================
    // ML EVALUATION SECTION
    // ================================================

    QGroupBox *mlEvaluationGroup = nullptr;


    QLabel *similarityScoreLabel = nullptr;

    QProgressBar *similarityProgressBar = nullptr;


    QLabel *recoverabilityScoreLabel = nullptr;

    QProgressBar *recoverabilityProgressBar = nullptr;


    QLabel *riskLevelLabel = nullptr;

    QLabel *recommendedMethodLabel = nullptr;

    QLabel *recommendationLabel = nullptr;


    // ================================================
    // CURRENT DRIVE
    // ================================================

    std::string currentDrivePath;

    char currentDriveLetter = '\0';
};