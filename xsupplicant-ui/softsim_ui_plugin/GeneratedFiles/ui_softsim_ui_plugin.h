/********************************************************************************
** Form generated from reading ui file 'softsim_ui_plugin.ui'
**
** Created: Wed Jan 21 11:59:27 2009
**      by: Qt User Interface Compiler version 4.3.4
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/

#ifndef UI_SOFTSIM_UI_PLUGIN_H
#define UI_SOFTSIM_UI_PLUGIN_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QDialog>
#include <QtGui/QDialogButtonBox>
#include <QtGui/QGridLayout>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QVBoxLayout>

class Ui_softsim_ui_pluginClass
{
public:
    QVBoxLayout *vboxLayout;
    QGridLayout *gridLayout;
    QLabel *label;
    QLineEdit *imsi;
    QLabel *label_2;
    QLineEdit *ki;
    QLabel *label_3;
    QLineEdit *sqn;
    QLabel *label_4;
    QLineEdit *amf;
    QLabel *label_5;
    QLineEdit *opc;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *softsim_ui_pluginClass)
    {
    if (softsim_ui_pluginClass->objectName().isEmpty())
        softsim_ui_pluginClass->setObjectName(QString::fromUtf8("softsim_ui_pluginClass"));
    softsim_ui_pluginClass->resize(370, 189);
    softsim_ui_pluginClass->setWindowIcon(QIcon(QString::fromUtf8(":/softsim_ui_plugin/Resources/simcard.png")));
    vboxLayout = new QVBoxLayout(softsim_ui_pluginClass);
    vboxLayout->setSpacing(6);
    vboxLayout->setMargin(11);
    vboxLayout->setObjectName(QString::fromUtf8("vboxLayout"));
    gridLayout = new QGridLayout();
    gridLayout->setSpacing(6);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    label = new QLabel(softsim_ui_pluginClass);
    label->setObjectName(QString::fromUtf8("label"));

    gridLayout->addWidget(label, 0, 0, 1, 1);

    imsi = new QLineEdit(softsim_ui_pluginClass);
    imsi->setObjectName(QString::fromUtf8("imsi"));
    imsi->setMaxLength(18);

    gridLayout->addWidget(imsi, 0, 1, 1, 1);

    label_2 = new QLabel(softsim_ui_pluginClass);
    label_2->setObjectName(QString::fromUtf8("label_2"));

    gridLayout->addWidget(label_2, 1, 0, 1, 1);

    ki = new QLineEdit(softsim_ui_pluginClass);
    ki->setObjectName(QString::fromUtf8("ki"));
    ki->setMaxLength(32);

    gridLayout->addWidget(ki, 1, 1, 1, 1);

    label_3 = new QLabel(softsim_ui_pluginClass);
    label_3->setObjectName(QString::fromUtf8("label_3"));

    gridLayout->addWidget(label_3, 2, 0, 1, 1);

    sqn = new QLineEdit(softsim_ui_pluginClass);
    sqn->setObjectName(QString::fromUtf8("sqn"));
    sqn->setMaxLength(12);

    gridLayout->addWidget(sqn, 2, 1, 1, 1);

    label_4 = new QLabel(softsim_ui_pluginClass);
    label_4->setObjectName(QString::fromUtf8("label_4"));

    gridLayout->addWidget(label_4, 3, 0, 1, 1);

    amf = new QLineEdit(softsim_ui_pluginClass);
    amf->setObjectName(QString::fromUtf8("amf"));
    amf->setMaxLength(4);

    gridLayout->addWidget(amf, 3, 1, 1, 1);

    label_5 = new QLabel(softsim_ui_pluginClass);
    label_5->setObjectName(QString::fromUtf8("label_5"));

    gridLayout->addWidget(label_5, 4, 0, 1, 1);

    opc = new QLineEdit(softsim_ui_pluginClass);
    opc->setObjectName(QString::fromUtf8("opc"));
    opc->setMaxLength(32);

    gridLayout->addWidget(opc, 4, 1, 1, 1);


    vboxLayout->addLayout(gridLayout);

    buttonBox = new QDialogButtonBox(softsim_ui_pluginClass);
    buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
    buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::NoButton|QDialogButtonBox::Ok);

    vboxLayout->addWidget(buttonBox);


    retranslateUi(softsim_ui_pluginClass);

    QMetaObject::connectSlotsByName(softsim_ui_pluginClass);
    } // setupUi

    void retranslateUi(QDialog *softsim_ui_pluginClass)
    {
    softsim_ui_pluginClass->setWindowTitle(QApplication::translate("softsim_ui_pluginClass", "3G Soft SIM Configuration", 0, QApplication::UnicodeUTF8));
    label->setText(QApplication::translate("softsim_ui_pluginClass", "IMSI :", 0, QApplication::UnicodeUTF8));
    label_2->setText(QApplication::translate("softsim_ui_pluginClass", "K :", 0, QApplication::UnicodeUTF8));
    label_3->setText(QApplication::translate("softsim_ui_pluginClass", "Sequence Number :", 0, QApplication::UnicodeUTF8));
    label_4->setText(QApplication::translate("softsim_ui_pluginClass", "AMF :", 0, QApplication::UnicodeUTF8));
    label_5->setText(QApplication::translate("softsim_ui_pluginClass", "OPc (Encrypted) :", 0, QApplication::UnicodeUTF8));
    Q_UNUSED(softsim_ui_pluginClass);
    } // retranslateUi

};

namespace Ui {
    class softsim_ui_pluginClass: public Ui_softsim_ui_pluginClass {};
} // namespace Ui

#endif // UI_SOFTSIM_UI_PLUGIN_H
