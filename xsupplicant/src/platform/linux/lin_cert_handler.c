/**
 * Linux certificate handler
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file lin_cert_handler.c
 *
 * \author chris@open1x.org
 *
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <errno.h>

#include "src/xsup_common.h"
#include "src/xsup_err.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/context.h"
#include "src/xsup_debug.h"
#include "../cert_handler.h"


////////////////////// Macros ////////////////////////
#define XENONE 0
#define S_IAMB  0x1FF
#define MODE_WR_UNMASKED ((0777)&(~022)&(0777))
#define SUBJECT 1
#define ISSUER 2
#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
#define FREE(p) if (p != NULL) {free(p); p=NULL;}
#define INVALID_CERT_PATH (-1)
#define INVALID_CERT (-1)
#define NO_CERT_PATH (-1)
#define ERROR_FILE_OPEN (-1)
#define MODE_WR_R_R 644
#define MODE_R_R_R 444
#define NO_CERTS_IN_STORE (-1)
#define EMPTY_CERT_LIST (-1)
#define ERROR_ALLOC (-1)
#define ERROR_BIO_READ (-1)
#define ERROR_X509_READ (-1)
#define ERROR_X509_WRITE (-1)
#define ERROR_FILE_OPEN (-1)
//////////////// Data Structures /////////////////////
typedef struct _pemfl_list
{
        int fl_index;
        char * filename;
        struct _pemfl_list *next;

}PEMFL_LIST;
///////////////////////////////////////////////////////
/////////////////////// GLOBALS ///////////////////////
char gStorePath[300];
PEMFL_LIST * pl_ca_list;
X509 *cur_X509_Obj = NULL;
///////////////////////////////////////////////////////
/////////////// Utils /////////////////////////////////
char * X509_NAME_to_str(X509_NAME *name,int fmt);
char * getToken(char *s_str,char * lbuff);
int get_pemfl_count(const char * pathname);
time_t ASN1_UTCTIME_get(const ASN1_UTCTIME *s);
char *getFriendlyname(char *sO,int iI);
char *getIssuername(char * location);
///////////////////////////////////////////////////////

/**
 * \brief Initialize the Linux certificate store.
 * /root/xsupplicant/certs is the default store path.
 * If it doesnot exist, create it.
 * \retval XENONE on success
 * \retval XEGENERROR on failure
 **/

int cert_handler_init()
{
        DIR * dirp = NULL;

        dirp = opendir("/root/xsupplicant");

        if(dirp)
        {
                closedir(dirp);
                dirp = NULL;
                dirp = opendir("/root/xsupplicant/certs");
                if(dirp)
                {
                        closedir(dirp);
                        dirp = NULL;
                }
                else
                {
                        if(mkdir("/root/xsupplicant/certs",MODE_WR_UNMASKED))
                                return XEGENERROR;
                }

 	    }
        else if(!mkdir("/root/xsupplicant",MODE_WR_UNMASKED))
        {
                if(mkdir("/root/xsupplicant/certs",MODE_WR_UNMASKED))
		               	return XEGENERROR;
		}
        else return XEGENERROR;

		strcpy(gStorePath,"/root/xsupplicant/certs");
        SSL_library_init();
        SSL_load_error_strings();

        return XENONE;
}

/**
 * \brief Close the certificate store handle.
 **/
void cert_handler_deinit()
{
	PEMFL_LIST * t = NULL;
	
	while(pl_ca_list)	
	{
		t = pl_ca_list->next;
		if(pl_ca_list->filename)
			FREE(pl_ca_list->filename);
		FREE(pl_ca_list);
		pl_ca_list = t;
	}
}

/**
 * \brief Parse the ASN.1 Encoded Subject information, and pull out things like the CN, 
 *        OU, O, etc.
 *
 * @param[in] pCertContext   A pointer to the certificate context for the certificate we want
 *                           to gather the data for.
 * @param[in,out] certinfo   A pointer to the structure that we will populate with the 
 *                           certificate information.
 *
 * \note Not all of the values listed in the structure will be present in all of the 
 *       certificates that we are looking at.   The caller should be prepared to deal
 *       with some (or perhaps all) of the fields being NULL.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
#if 0
int cert_handler_get_info(PCCERT_CONTEXT  pCertContext, cert_info *certinfo)
{
  return -1;
}
#endif

/**
 * \brief Given the certificate name, get the information about it.
 *
 * @param[in] certname   The certificate's "friendly" name that we want to use.
 * @param[in,out] certinfo   A pointer to the structure that will contain all
 *                           of the certificate information requested.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
/////////////////////////////////////////////////////////////////////////
//  	THIS FUNCTION IS NOT USED
/////////////////////////////////////////////////////////////////////////
int cert_handler_get_info_from_name(char *certname, cert_info *certinfo)
{
  return -1;
}

/**
 * \brief Free all of the fields that are included in a cert_info structure.
 *
 * @param[in] cinfo   A pointer to the structure that we want to free the members of.
 **/
void cert_handler_free_cert_info(cert_info *cinfo)
{
	if(cinfo)
	{
		if(cinfo->C)	FREE(cinfo->C);
		if(cinfo->CN) FREE(cinfo->CN);
		if(cinfo->O) FREE(cinfo->O);
		if(cinfo->L) FREE(cinfo->L);
		if(cinfo->OU) FREE(cinfo->OU);
		if(cinfo->S) FREE(cinfo->S);
	}
	cinfo = NULL;
}

/**
 * \brief Determine the number of root CA certificates are in the store that
 *        can be used for server authentication.
 *
 * \retval -1 on error
 * \retval >=0 is the number of certificates that will be in the list.
 **/
int cert_handler_num_root_ca_certs()
{
	int cnt = 0;
	debug_printf(DEBUG_INT,"NUM_ROOT_CA_CERTS:cnt[%s]\n",gStorePath);
	cnt = get_pemfl_count(gStorePath);
	debug_printf(DEBUG_INT,"NUM_ROOT_CA_CERTS:cnt[%d]\n",cnt);
  	return cnt;
}

/**
 * \brief Free the memory that was allocated to store the certificate enumeration.
 *
 * @param[in] numcas   The number of CAs that are represented in the enumeration.
 * @param[in] cas   The array of CA names.
 **/
void cert_handler_free_cert_enum(int numcas, cert_enum **cas)
{
	cert_enum *casa = NULL;
	int i = 0;

	casa = (*cas);

	for (i = 0; i < numcas; i++)
	{
		if(casa)
		{
			if (casa[i].certname != NULL) FREE(casa[i].certname);
                	if (casa[i].friendlyname != NULL) FREE(casa[i].friendlyname);
                	if (casa[i].issuer != NULL) FREE(casa[i].issuer);
		}
		else casa = NULL;
	}
	if(*cas)
		FREE((*cas));
	(*cas) = NULL;
}

/**
 * \brief Enumerate root CA certificates that are in the store that
 *        can be used for server authentication.
 *
 * @param[in] numcas   An integer the specifies the number of CA certificates we are expected to
 *                     return.  This value should come from the cert_handler_num_root_ca_certs().
 *                     On return, this will contain the number of certificates that are actually in
 *                     the array.
 *
 * @param[in,out] cas   An array of certificates that contains the number of certificates defined
 *                      by numcas.
 *
 * \retval -1 on error
 * \retval 0 on success
 **/
int cert_handler_enum_root_ca_certs(int *numcas, cert_enum **cas)
{
	cert_enum *casa = NULL;
	PEMFL_LIST * tmp_ca_list = NULL;;
	int cert_index = 0,sz = 0,i = 0;
	char tmp_str[300],cName[50];
 	cert_info ci;

	
	debug_printf(DEBUG_INT,"TRACE-1:numcas[%d]\n",*numcas);
	if(!(*numcas)) 	return NO_CERTS_IN_STORE;	// No certs in store

	get_pemfl_count_and_build_list(gStorePath);	
	debug_printf(DEBUG_INT,"TRACE-2:gStorePath[%s]\n",gStorePath);
	if(!pl_ca_list) return EMPTY_CERT_LIST;
	tmp_ca_list = pl_ca_list;
	casa = (cert_enum*)malloc(sizeof(cert_enum)*(*numcas + 1));
	if(!casa) return ERROR_ALLOC;		// Unable to allocate memory.
	
	while(tmp_ca_list && cert_index <= *numcas)
	{
		i = 0;
		time_t ctm;
       		struct tm *tm_local;

		casa[cert_index].storetype = strdup("LINUX");
		casa[cert_index].location = tmp_ca_list->filename;
		strcpy(tmp_str, tmp_ca_list->filename);
		sz = strlen( tmp_ca_list->filename);
		while(tmp_str[sz-1]!= '/') sz--;
		casa[cert_index].certname = (char*)malloc(sizeof(char)* (strlen(tmp_ca_list->filename)-sz+1));
		while(tmp_str[sz]) casa[cert_index].certname[i++] = tmp_str[sz++];
		casa[cert_index].certname[i] = '\0';
		cert_handler_get_info_from_store(NULL,tmp_ca_list->filename, &ci);
		casa[cert_index].friendlyname = getFriendlyname(ci.O,tmp_ca_list->fl_index);				
		casa[cert_index].commonname = ci.CN;
		casa[cert_index].issuer = getIssuername(tmp_ca_list->filename);
		ctm = time(NULL);
       	ctm -= ctm%(60*60*24);
       	ctm = ASN1_UTCTIME_get(X509_get_notAfter(cur_X509_Obj));
       	tm_local = localtime(&ctm);
		casa[cert_index].day = tm_local->tm_mday;
		casa[cert_index].month = tm_local->tm_mon+1; // Add 1, as month count starts from 0.
		casa[cert_index].year = tm_local->tm_year+1900; // Add 1900, as year count starts from 1900.
		cert_index++;
		tmp_ca_list = tmp_ca_list->next;
	}
	*cas = casa;	
  	return 0;
}

/**
 ** \brief Get info for the specified certificate.
 **
 ** @param[in] storetype Type of the certificate - PEM, DER.
 **
 ** @param[in] location  Location of the certificate.
 **
 ** @param[out] certinfo Stucture which will be filled with the
 ** 			 details of the specified certificate.
 ** \retval -1 on error
 ** \retval 0 on success
 ***/

int cert_handler_get_info_from_store(char *storetype, char *location, cert_info *certinfo) 
{
	X509* cert = NULL;
        BIO* bio_cert = NULL;
	long datalen = 0;
	X509_NAME *name=NULL;
	char * cert_buff = NULL;

	debug_printf(DEBUG_INT,"TRACE-3:location[%s]\n",location);
	bio_cert = BIO_new_file(location, "rb");

	if(bio_cert)
    {
		PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
		if(!cert) return INVALID_CERT;
	}
    else return ERROR_BIO_READ;	//Error:cannot read bio_cert.
	
	name = X509_get_subject_name(cert);

    if(name) 
	{
		cert_buff = X509_NAME_to_str(name,SUBJECT);
		if(!cert_buff) return INVALID_CERT;
	}
    else return ERROR_X509_READ; //Error:Unable to fetch App-Data.

	certinfo->C = getToken("C",cert_buff);
	certinfo->O = getToken("O",cert_buff);
	certinfo->OU = getToken("OU",cert_buff);
	certinfo->CN = getToken("CN",cert_buff);
	certinfo->S = getToken("ST",cert_buff);
	certinfo->L = getToken("L",cert_buff);
	
	cur_X509_Obj = cert;
	return 0;
}

/**
 ** \brief Add a new certificate to the store.
 **
 ** @param[in] location  Location of the new certificate.
 **                      
 ** \retval -1 on error
 ** \retval 0 on success
 **/

int cert_handler_add_cert_to_store(char *path_to_cert)
{
	char new_cert_name[80],path_to_store[300];
	char * tmp_str = strdup(path_to_cert);
	int sz = 0,i = 0;
	X509* cert = NULL;
    BIO* bio_cert = NULL;
	FILE * outfl = NULL;

	
	debug_printf(DEBUG_INT,"TRACE-4_0:path_to_cert[%s]\n",path_to_cert);
	if(path_to_cert)
	{
	    bio_cert = BIO_new_file(path_to_cert, "rb");

	debug_printf(DEBUG_INT,"TRACE-4_1:BIO_open\n");
        if(bio_cert)
        {
			PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
	debug_printf(DEBUG_INT,"TRACE-4_2:BIO_read\n");
	        if(!cert) return INVALID_CERT;
			sz = strlen(tmp_str);
            while(tmp_str[sz]!='/' && sz>0) sz--;
            while(tmp_str[sz]) new_cert_name[i++]=tmp_str[sz++];
            new_cert_name[i]='\0';
            i = 0;
            strcpy(path_to_store,gStorePath);
            strcat(path_to_store,new_cert_name);
	debug_printf(DEBUG_INT,"TRACE-4_3:path_to_store[%s]\n",path_to_store);
			outfl = fopen(path_to_store,"w+");
			if(outfl)			
			{
	debug_printf(DEBUG_INT,"TRACE-4_4:[%s] opened\n",path_to_store);
				if(!PEM_write_X509(outfl,cert))
				{
	debug_printf(DEBUG_INT,"TRACE-4_5:ERROR\n");
					if(tmp_str) FREE(tmp_str);
					if(outfl) fclose(outfl);
					return ERROR_X509_WRITE;
				}
			}
			else 
			{
	debug_printf(DEBUG_INT,"TRACE-4_6:ERROR:Unable to open %s\n",path_to_store);
				if(tmp_str) FREE(tmp_str);
				if(outfl) fclose(outfl);
				return ERROR_FILE_OPEN;
			}
        }
	    else
		{
	debug_printf(DEBUG_INT,"TRACE-4_7:ERROR:BIO failed\n");
			if(tmp_str) FREE(tmp_str);
			if(outfl) fclose(outfl);
			return ERROR_BIO_READ; //Error:cannot read bio_cert.
		}
	}
	else 
	{
	debug_printf(DEBUG_INT,"TRACE-4_8:Invalid path to cert[%s]\n",path_to_cert);
		if(tmp_str) FREE(tmp_str);
		if(outfl) fclose(outfl);
		return NO_CERT_PATH; // ERROR:NO cert path
	}

	debug_printf(DEBUG_INT,"TRACE-4_9:ALL DONE.\n");
	if(tmp_str) FREE(tmp_str);
	if(outfl) fclose(outfl);
return 0;
}

////////////////////////// Utils /////////////////////////////

/**
 ** \brief Extract cert details (Subject/Issuer) as a string .
 **
 ** @param[in] name  X509 obj(container) of the certificate.
 **                      
 ** @param[in] fmt  Specifies the format for the output string.
 **                      
 ** \retval NULL on error
 ** \retval a valid string on success
 **/

char * X509_NAME_to_str(X509_NAME *name, int fmt)
{
        BIO     *membuf = BIO_new(BIO_s_mem());
        int i=0,nid=0,count = X509_NAME_entry_count(name);
        X509_NAME_ENTRY *e;
        const char *field_name;
        char       *sp;
        char       *dp;
        ASN1_STRING *v;
        size_t     size;
		int do_once = 1;

        (void) BIO_set_close(membuf, BIO_CLOSE);
        for (i = 0; i < count; i++)
        {
                e = X509_NAME_get_entry(name, i);
                nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
                v = X509_NAME_ENTRY_get_data(e);
                field_name = OBJ_nid2sn(nid);
                if (!field_name)
                        field_name = OBJ_nid2ln(nid);
		if(fmt == SUBJECT)
                	BIO_printf(membuf, "/%s=", field_name);
		else if(fmt == ISSUER)
		{
			if(do_once) {BIO_printf(membuf, " %s=", field_name); do_once = 0;}
			else BIO_printf(membuf, ", %s=", field_name);
		}
                ASN1_STRING_print_ex(membuf, v,
                                 ((ASN1_STRFLGS_RFC2253 & ~ASN1_STRFLGS_ESC_MSB)
                                  | ASN1_STRFLGS_UTF8_CONVERT));
        }

        i = 0;
        BIO_write(membuf, &i, 1);
        size = BIO_get_mem_data(membuf, &sp);

        //BIO_free(membuf);


        return sp;
}

/**
 ** \brief Extract tokens(details) for the specified field-string.
 **
 ** @param[in] s_str Specifies the field-string for which the content has to be fetched.
 **                      
 ** @param[in] lbuff It is the buffer from which the tokens will be extracted.
 **                      
 ** \retval NULL on error
 ** \retval a valid string on success
 **/

char * getToken(char *s_str,char * lbuff)
{
	char tag_str[20],sarg[50];
	int not_done = 1,i = 0;
	char *sContent = NULL;

	sContent = (char*)malloc(50);
	while(not_done)
	{
		while(*lbuff && *lbuff != '/') lbuff++;
		lbuff++;
		while(*lbuff && *lbuff != '=')
		{ tag_str[i++] = *lbuff; lbuff++; }
		tag_str[i] = '\0';
		if(!strcmp(tag_str,s_str)) 
		{
			not_done = 0;
			lbuff++; 
			i = 0;	
			while(*lbuff && *lbuff != '/') 
			{ 
			sarg[i++] = *lbuff; lbuff++; }
			sarg[i]='\0';
			strcpy(sContent,sarg);
		}
		else {memset(&tag_str,'\0',20); i = 0;}
	}
	return sContent;
}

/**
 ** \brief Count the number of DER files in the specified directory.
 **
 ** @param[in] pathname Location to be searched in for DER files.
 **                      
 ** \retval -1 on error
 ** \retval count of files on success
 **/

int get_pemfl_count(const char * pathname)
{
        struct dirent* d;
        struct stat f_info;
        char abs_flpath[100];
        int pemcnt = 0;
		X509* cert = NULL;
        BIO* bio_cert = NULL;
        char *tmp_str;

	debug_printf(DEBUG_INT,"Store pathname is [%s]\n",pathname);
        DIR* dirp = opendir(pathname);
        if(dirp)
        {
	    debug_printf(DEBUG_INT,"Store pathname is opened[%s]\n",pathname);
            for (d = readdir(dirp) ; d!=NULL ; d = readdir(dirp))
            {
	        //Don't consider '.' and '..'
                if (strcmp(".", d->d_name) && strcmp("..", d->d_name))
                {
					strcpy(abs_flpath,pathname);
                    if(abs_flpath[strlen(abs_flpath)-1]!= '/') strcat(abs_flpath,"/");
                    strcat(abs_flpath,d->d_name);
                    if (!stat(abs_flpath, &f_info))
                    {
						// Exclude directories, consider only files.
                        if (S_ISREG(f_info.st_mode))
                        {
							tmp_str = strdup(d->d_name);
                            while(*tmp_str && *tmp_str != '.') tmp_str++;
                            // Count only files with .pem extension.
                            if(!strcmp(tmp_str,".pem")) 
							{
	debug_printf(DEBUG_INT,"TRACE-6:PEM file[%s]\n",abs_flpath);
								bio_cert = NULL;
								cert = NULL;
								bio_cert = BIO_new_file(abs_flpath, "rb");
					            if(bio_cert)
								{
	debug_printf(DEBUG_INT,"TRACE-7:Valid PEM cert\n");
                        			PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
									if(cert)
									{
	debug_printf(DEBUG_INT,"TRACE-8:Valid PEM cert\n");
									  pemcnt++;
									}
								}
							}
						}
					}
                	}
		}
	}
        return pemcnt;
}

/**
 ** \brief Build the list of DER files.
 **
 ** @param[in] pathname Location to be searched in for DER files.
 **                      
 ** \retval 0 on error
 ** \retval count of files on success
 **/

int get_pemfl_count_and_build_list(const char * pathname)
{

    struct dirent* d;
    struct stat f_info;
    char abs_flpath[100];
    DIR* dirp = opendir(pathname);
    char *tmp_str;
    int pemcnt = 0;
    PEMFL_LIST * new_pemfl = NULL, *tmp_pl = NULL;
	X509* cert = NULL;
    BIO* bio_cert = NULL;

	// We need to build list afresh
    if(pl_ca_list)
    {
		free(pl_ca_list);
        pl_ca_list = NULL;
    }

    if(dirp)
    {
		for (d = readdir(dirp) ; d!=NULL ; d = readdir(dirp))
        {
			if ((0 != strcmp(".", d->d_name)) && (0 != strcmp("..", d->d_name)))
            {
				strcpy(abs_flpath,pathname);
                if(abs_flpath[strlen(abs_flpath)-1]!= '/') strcat(abs_flpath,"/");
                strcat(abs_flpath,d->d_name);

				if (!stat(abs_flpath, &f_info))
                {
					if (S_ISREG(f_info.st_mode))
                    {
						tmp_str = strdup(d->d_name);
                        while(*tmp_str && *tmp_str != '.') tmp_str++;
                        if(!strcmp(tmp_str,".pem"))
                        {
							bio_cert = NULL;
							cert = NULL;
							bio_cert = BIO_new_file(abs_flpath, "rb");
                            if(bio_cert)
                            {
								PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
                                if(cert) 
								{
									pemcnt++;
                                	tmp_pl = pl_ca_list;
	                               	if(!tmp_pl)
        	                       	{
                	                   	pl_ca_list = (PEMFL_LIST*)malloc(sizeof(PEMFL_LIST));
	                	                pl_ca_list->filename = strdup(abs_flpath);
										pl_ca_list->fl_index = pemcnt;
                	                    pl_ca_list->next = NULL;
                        			}
                                	else
                                    {
										while(tmp_pl->next) tmp_pl = tmp_pl->next;
	                                    new_pemfl = (PEMFL_LIST*)malloc(sizeof(PEMFL_LIST));
        	                            new_pemfl->filename = strdup(abs_flpath);
	        	                        new_pemfl->fl_index = pemcnt;
        	        	                new_pemfl->next = NULL;
                	        	        tmp_pl->next = new_pemfl;
                        	        }
								}
								else cert = NULL;
							}
							else bio_cert = NULL;
						}
					}
				}
			}
		}
	}
    else return 0; 	//ERROR:Unable to open dir.
    return pemcnt;
}

/**
 ** \brief Convert ASN time to time_t format.
 **
 ** @param[in] s Pointer to ASN_UTC structure.
 **                      
 ** \retval 0 on error
 ** \retval time in time_t format on success
 **/

time_t ASN1_UTCTIME_get(const ASN1_UTCTIME *s)
{
        struct tm tm;
        int offset;

        memset(&tm,'\0',sizeof tm);

        tm.tm_year=g2(s->data);
        if(tm.tm_year < 50)
                tm.tm_year+=100;
        tm.tm_mon=g2(s->data+2)-1;
        tm.tm_mday=g2(s->data+4);
        tm.tm_hour=g2(s->data+6);
        tm.tm_min=g2(s->data+8);
        tm.tm_sec=g2(s->data+10);
        if(s->data[12] == 'Z')
                offset=0;
        else
        {
                offset=g2(s->data+13)*60+g2(s->data+15);
                if(s->data[12] == '-')
                        offset= -offset;
        }

        return mktime(&tm)-offset*60;
}

/**
 ** \brief Extract issuer name from the certificate.
 **
 ** @param[in] location Location of the certificate.
 **                      
 ** \retval NULL on error
 ** \retval Valid string on success
 **/

char *getIssuername(char * location)
{
	X509* cert = NULL;
        BIO* bio_cert;
        long datalen = 0;
        X509_NAME *name=NULL;
        char * cert_buff = NULL;

        bio_cert = BIO_new_file(location, "rb");

        if(bio_cert)
                PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
        else
        //Error:cannot read bio_cert.
         return NULL;

        name = X509_get_subject_name(cert);

        if(name) cert_buff = X509_NAME_to_str(name,ISSUER);
        else
        //Error:Unable to fetch App-Data.
        return NULL;

	return cert_buff;		
}

/**
 ** \brief Prepare friendly name for the certficate.
 **        Format of friendly name will be like - 
 **	   <Organization Name>_<cert index>	
 ** @param[in] sO Organization name.
 **                      
 ** @param[in] sI Cert index.
 **                      
 ** \retval NULL on error
 ** \retval Valid string on success
 **/

char *getFriendlyname(char *sO,int iI)
{
	char * sFN = NULL;
	char * sI = NULL;
	
	sFN = (char*)malloc(strlen(sO)+6);
	sI = (char*)malloc(6);
	sprintf(sI,"_%d",iI);
	strcpy(sFN,sO);
	strcat(sFN,sI);
	
	return sFN;
}


/**
 * \brief Return the number of user certificates in our store.
 *
 * \retval -1 on error
 * \retval >=0 is the number of certificates that will be in the list.
 **/
int cert_handler_num_user_certs()
{
#warning Implement!
  return 0;
}

int cert_handler_enum_user_certs(int *numcer, cert_enum **cer)
{
#warning Implement!
  return -1;
}
