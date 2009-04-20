#include <windows.h>
#include <shlobj.h>
#include <QMessageBox>
#include "softsim_ui_plugin.h"

softsim_ui_plugin::softsim_ui_plugin(QWidget *parent, Qt::WFlags flags)
	: QDialog(parent, flags)
{
	ui.setupUi(this);
	load_sim_config();
	update_sim_config();

	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(save_data()));
}

softsim_ui_plugin::~softsim_ui_plugin()
{
	disconnect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
	disconnect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(save_data()));
}

void softsim_ui_plugin::process_line(char *line)
{
	char *key = NULL, *value = NULL;
	int i = 0;

	if (line[0] == '#') return;

	key = line;
	while ((i < strlen(line)) && (line[i] != '=')) i++;

	line[i] = 0x00;

	value = (char *)&line[i+1];

	if (_stricmp("imsi", key) == 0)
	{
		// It is an imsi.
		imsi = value;
	}
	else if (_stricmp("k", key) == 0)
	{
		// It is a K
		ki = value;
	}
	else if (_stricmp("sqn", key) == 0)
	{
		sqn = value;
	}
	else if (_stricmp("amf", key) == 0)
	{
		amf = value;
	}
	else if (_stricmp("oc", key) == 0)
	{
		opc = value;
	}
}

int softsim_ui_plugin::load_config_from_path(char *path)
{
	FILE *fp = NULL;
	char line[1000];

	fp = fopen(path, "r");
	if (fp == NULL) return -1;

	while (fscanf(fp, "%s", &line) != EOF)
	{
		process_line(line);
	}

	fclose(fp);

	return 0;
}

int softsim_ui_plugin::write_config_to_path(char *path)
{
	FILE *fp = NULL;

	fp = fopen(path, "w");
	if (fp == NULL) return -1;

	fprintf(fp, "IMSI=%s\n", imsi.toAscii().data());
	fprintf(fp, "K=%s\n", ki.toAscii().data());
	fprintf(fp, "AMF=%s\n", amf.toAscii().data());
	fprintf(fp, "OC=%s\n", opc.toAscii().data());
	fprintf(fp, "SQN=%s\n", sqn.toAscii().data());

	fclose(fp);

	return 0;
}

int softsim_ui_plugin::load_sim_config()
{
	TCHAR szMyPath[MAX_PATH];
	char *path = NULL;

	if (FAILED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, (LPSTR)&szMyPath)))
	  {
		  printf("Couldn't determine the path to the local common app data.\n");
		  return NULL;
	  }

	path = (char *)malloc(strlen((char *)&szMyPath)+strlen("usim.txt")+3);
	if (path == NULL) return -1;

	memset(path, 0x00, strlen((char *)&szMyPath)+strlen("usim.txt")+3);

	strcpy(path, (char *)&szMyPath);
	strcat(path, "\\usim.txt");

	return load_config_from_path(path);
}

void softsim_ui_plugin::update_sim_config()
{
	ui.ki->setText(ki);
	ui.imsi->setText(imsi);
	ui.opc->setText(opc);
	ui.amf->setText(amf);
	ui.sqn->setText(sqn);
}

void softsim_ui_plugin::get_sim_config()
{
	ki = ui.ki->text();
	imsi = ui.imsi->text();
	opc = ui.opc->text();
	amf = ui.amf->text();
	sqn = ui.sqn->text();
}

void softsim_ui_plugin::save_data()
{
	TCHAR szMyPath[MAX_PATH];
	char *path = NULL;

	if (FAILED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, (LPSTR)&szMyPath)))
	  {
		  printf("Couldn't determine the path to the local common app data.\n");
		  return;
	  }

	path = (char *)malloc(strlen((char *)&szMyPath)+strlen("usim.txt")+3);
	if (path == NULL) return;

	memset(path, 0x00, strlen((char *)&szMyPath)+strlen("usim.txt")+3);

	strcpy(path, (char *)&szMyPath);
	strcat(path, "\\usim.txt");

	get_sim_config();

	write_config_to_path(path);

	QMessageBox::information(this, tr("Data Updated"), tr("Your soft SIM configuration has been updated."));
	accept();
}

