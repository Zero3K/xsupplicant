#ifndef SOFTSIM_UI_PLUGIN_H
#define SOFTSIM_UI_PLUGIN_H

#include <QtGui/QDialog>
#include "ui_softsim_ui_plugin.h"

class softsim_ui_plugin : public QDialog
{
	Q_OBJECT

public:
	softsim_ui_plugin(QWidget *parent = 0, Qt::WFlags flags = 0);
	~softsim_ui_plugin();

private slots:
	void save_data();

private:
	void process_line(char *line);
	int load_config_from_path(char *path);
	int write_config_to_path(char *path);
	int load_sim_config();
	void update_sim_config();
	void get_sim_config();

	Ui::softsim_ui_pluginClass ui;

	QString imsi;
	QString ki;
	QString opc;
	QString amf;
	QString sqn;
};

#endif // SOFTSIM_UI_PLUGIN_H
