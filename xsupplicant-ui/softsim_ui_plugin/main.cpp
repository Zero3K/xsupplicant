#include <QtGui/QApplication>
#include "softsim_ui_plugin.h"

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	softsim_ui_plugin w;
	w.show();
	a.connect(&a, SIGNAL(lastWindowClosed()), &a, SLOT(quit()));
	return a.exec();
}
