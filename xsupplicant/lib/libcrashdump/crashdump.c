/**
 * Framework to trap crashes on an OS and create information needed for debugging the crash.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file crashdump.c
 *
 * \author chris@open1x.org
 **/

#ifdef WINDOWS
#define _CRT_SECURE_NO_WARNINGS
#else
#define _strdup  strdup
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#ifdef WINDOWS
#include <direct.h>
#include <io.h>
#endif

#include "zip.h"
#include "crashdump.h"
#include "crash_handler.h"

#ifdef WINDOWS
#define USEWIN32IOAPI
#include "iowin32.h"

#define unlink  _unlink
#endif

//#define DEBUG   1   ///< Uncomment this to have a file written with debug output.

typedef struct {
	char *filename;
	char unlink;		///< 0 if we should leave it, 1 if we should delete it.
} cfiles;

cfiles *crashfiles;		///< This will be allocated as an array of values that we will want to add to our crash zip file if we crash.
int num_crashfiles;		///< The number of crash files that we have listed in the array above.

char *curuser_conf = NULL;

char *zipdumppath;		///< The full path (including filename) to where we want the zipped dump file to land.

/**
 * \brief Init the crashdump library by setting any variable state that we need to set.
 **/
void crashdump_init(char *zipdumppath_in)
{
	crashfiles = NULL;
	num_crashfiles = 0;
	zipdumppath = _strdup(zipdumppath_in);
}

/**
 * \brief Add the current user's configuration to the crash list.
 **/
void crashdump_add_curuser_conf(char *conf_path)
{
	crashdump_remove_curuser_conf();
	curuser_conf = _strdup(conf_path);
}

/**
 * \brief Remote the current user's configuration from the crash list.
 **/
void crashdump_remove_curuser_conf()
{
	if (curuser_conf != NULL) {
		free(curuser_conf);
		curuser_conf = NULL;
	}
}

/**
 * \brief Add a file to our crash dump gathering list.  The files that are added will be picked up and stuck in a .zip file
 *        in the event of a crash.  (In the event of a water landing, the files cannot be used for flotation.)
 *
 * @param[in] filename   The full path to the file that we want to add to our zip file.
 * @param[in] unlink   Should we delete the file after gathering it.
 *
 * \retval CRASHDUMP_ALREADY_EXISTS if the file is already in the list.
 * \retval CRASHDUMP_NO_ERROR on success
 * \retval CRASHDUMP_CANT_ADD on failure.
 **/
int crashdump_add_file(char *filename, char unlink)
{
	void *oldptr = NULL;
	int i;

	for (i = 0; i < num_crashfiles; i++) {
		if (strcmp(filename, crashfiles[i].filename) == 0) {
			fprintf(stderr, "File %s == %s!  Skipping!\n", filename,
				crashfiles[i].filename);
			return CRASHDUMP_ALREADY_EXISTS;
		}
	}

	num_crashfiles++;

	oldptr = crashfiles;
	crashfiles =
	    realloc(crashfiles, ((sizeof(cfiles) + 1) * (num_crashfiles)));
	if (crashfiles == NULL) {
		// ACK!  We couldn't allocate more memory!
		num_crashfiles--;
		fprintf(stderr, "Couldn't realloc memory!\n");
		crashfiles = oldptr;
		return CRASHDUMP_CANT_ADD;
	}

	crashfiles[num_crashfiles - 1].filename = _strdup(filename);
	if (crashfiles[num_crashfiles - 1].filename == NULL) {
		num_crashfiles--;
		fprintf(stderr, "Couldn't copy filename!\n");
		return CRASHDUMP_CANT_ADD;
	}

	crashfiles[num_crashfiles - 1].unlink = unlink;

	return CRASHDUMP_NO_ERROR;
}

#ifdef WINDOWS
/**
 * \brief A helper function (for Windows) to get the data and time for a file.
 **/
uLong filetime(f, tmzip, dt)
char *f;			/* name of file to get info on */
tm_zip *tmzip;			/* return value: access, modific. and creation times */
uLong *dt;			/* dostime */
{
	int ret = 0;
	{
		FILETIME ftLocal;
		HANDLE hFind;
		WIN32_FIND_DATA ff32;

		hFind = FindFirstFile(f, &ff32);
		if (hFind != INVALID_HANDLE_VALUE) {
			FileTimeToLocalFileTime(&(ff32.ftLastWriteTime),
						&ftLocal);
			FileTimeToDosDateTime(&ftLocal, ((LPWORD) dt) + 1,
					      ((LPWORD) dt) + 0);
			FindClose(hFind);
			ret = 1;
		}
	}
	return ret;
}
#endif

/**
 * \brief Store a file in to an open ZIP file.
 *
 * @param[in] filename   The file we want to add to the zip archive.
 * @param[in] zf   A handle to the zip archive we want to add the file to.
 *
 * \retval 0 on success
 * \retval -1 on error.
 **/
int crashdump_store_file_in_zip(char *filename, zipFile * zf)
{
	FILE *fin = NULL;
	int size_read;
	zip_fileinfo zi;
	int err = 0;
	char buf[16384];
	int size_buf = 16384;
	int x = 0;
	char *shortfname = NULL;	// The filename part of a file to add to the zip.

	fin = fopen(filename, "rb");
	if (fin == NULL) {
		printf("Error opening %s for reading! (Skipping)\n", filename);
#ifdef DEBUG
		fprintf(tempf, "Error opening %s for reading!  (Skipping)\n",
			filename);
		fflush(tempf);
#endif
		return 0;
	}

	memset(&zi, 0x00, sizeof(zi));
#ifdef WINDOWS
	filetime(filename, &zi.tmz_date, &zi.dosDate);	// Get the date/time of the file.
#else
#warning Implement for your OS!
#endif  // WINDOWS

	// Find the filename part of the file in the list.
	x = (int)strlen(filename);
	while ((x >= 0) && (filename[x] != '\\'))
		x--;

	if (x < 0) {
		// This will probably fail, but give it a shot anyway.
		shortfname = filename;
	} else {
		shortfname = (char *)&filename[x + 1];
	}

	err =
	    zipOpenNewFileInZip3(zf, shortfname, &zi, NULL, 0, NULL, 0, NULL,
				 Z_DEFLATED, 9, 0, -MAX_WBITS, DEF_MEM_LEVEL,
				 Z_DEFAULT_STRATEGY, NULL, 0);
	if (err != ZIP_OK) {
		printf("Error creating file in zip file!\n");
#ifdef DEBUG
		fprintf(tempf, "Error creating file '%s' in zip file!\n",
			shortfname);
		fflush(tempf);
#endif
		return -1;
	}

	do {
		err = ZIP_OK;

		size_read = (int)fread(buf, 1, size_buf, fin);
		if (size_read < size_buf) {
			if (feof(fin) == 0) {
				printf("Error reading file!\n");
				err = ZIP_ERRNO;
			}
		}

		if (size_read > 0) {
			err = zipWriteInFileInZip(zf, buf, size_read);
			if (err < 0) {
				printf("Error writing in zip file!\n");
				return -1;
			}
		}
	} while ((err == ZIP_OK) && (size_read > 0));

	if (fin)
		fclose(fin);

	if (err < 0) {
		printf("Error writing zip file!\n");
		return -1;
	}

	err = zipCloseFileInZip(zf);
	if (err != ZIP_OK) {
		printf("Error closing file in zip!\n");
		return -1;
	}

	return 0;
}

/**
 * \brief If we manage to crash, this function will be called.  It is expected to gather up all of the files
 *        from the file list, and put them in the right zip file.
 *
 * @param[in] destoverride  --  If this is NULL, then the destination specified by the crashdump_init()
 *                              call will be used to store the resulting .zip file.  If it is
 *                              NOT NULL, then the parameter specified will be used.  The idea
 *                              here is to allow this function to be called in a non-crash
 *                              situation to gather data that can later be used to help debug.
 *
 * \note This is going to need to be changed a bit to support OSes other than Windows!
 **/
void crashdump_gather_files(char *destoverride)
{
	zipFile zf = NULL;
	zlib_filefunc_def ffunc;
	char *path_to_use = NULL;
	int i = 0;
	int err = 0;

#ifdef DEBUG
	FILE *tempf = NULL;

#ifdef WINDOWS
	tempf = fopen("c:\\outdata.txt", "w");
#else
#warning Open the file in the right place for your OS!
#endif
	fprintf(tempf, "Started dumping data.\n");
	fflush(tempf);
#endif

	if (destoverride != NULL) {
		path_to_use = destoverride;
	} else {
		path_to_use = zipdumppath;
	}

#ifdef WINDOWS
	fill_win32_filefunc(&ffunc);
#else
#warning Implement for your OS!
#endif // WINDOWS

#ifdef DEBUG
	fprintf(tempf, "File func done.\n");
	fprintf(tempf, "path_to_use = %s\n", path_to_use);
	fflush(tempf);
#endif

	zf = zipOpen2(path_to_use, 0, NULL, &ffunc);
	if (zf == NULL) {
		printf("Couldn't create zip file!\n");
#ifdef DEBUG
		fprintf(tempf, "Couldn't create zip file.\n");
		fflush(tempf);
#endif
		return;
	}

	i = 0;
#ifdef DEBUG
	fprintf(tempf, "i = %d  num_crashfiles = %d\n", i, num_crashfiles);
	fflush(tempf);
#endif
	while (i < num_crashfiles) {
		// If we aren't successful, then just bail out.
		if (crashdump_store_file_in_zip(crashfiles[i].filename, zf) !=
		    0)
			return;

		if (crashfiles[i].unlink == 1)
			unlink(crashfiles[i].filename);	// We are done with it.
		i++;
	}

	if (curuser_conf != NULL)
		crashdump_store_file_in_zip(curuser_conf, zf);

	err = zipClose(zf, NULL);
	if (err != ZIP_OK) {
		printf("Error closing zip file!\n");
		return;
	}
}

/**
 * \brief Clean up after our crash dump library.  This will only be called if the program goes through a normal termination
 *        process.
 **/
void crashdump_deinit()
{
	int i = 0;

	crash_handler_cleanup();

	for (i = 0; i < num_crashfiles; i++) {
		if (crashfiles[i].filename != NULL)
			free(crashfiles[i].filename);
	}

	free(crashfiles);
	free(zipdumppath);
}
