#ifndef INTERFACECTRL_H
#define INTERFACECTRL_H

#include <QObject>
#include <QDialog>
#include <QLabel>

#include "Emitter.h"
#include "xsupcalls.h"

class InterfaceCtrl : public QDialog
{
	Q_OBJECT

public:
	InterfaceCtrl(bool takingCtrl, Emitter *pEmitter, XSupCalls *pSupplicant, QWidget *parent);
	~InterfaceCtrl();

	bool updateSupplicant();

private:
	XSupCalls *m_pSupplicant;
	Emitter *m_pEmitter;

	QLabel *m_pText;
	QVBoxLayout *m_pLayout;

	bool xsupCtrl;
};

#endif // INTERFACECTRL_H
