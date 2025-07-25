#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>

#ifdef USE_TLS
#include <mbedtls/net_sockets.h>
#include <mbedtls/private_access.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#endif

#define MAX_REQ 4096
#define MAX_PATH 1024
#define MAX_FILES 1000
#define PORT 8080
#define SANDBOX_LIMIT 1000000
int dev_mode=0, use_fork=0, use_lua=0, use_db=0;
unsigned char *zip_data = NULL;
size_t zip_size = 0;
long zip_start_offset = 0; 
bool sandbox_mode = false;
bool watch_mode = false;
static time_t last_zip_mtime = 0;
static time_t last_db_reload=0;
int use_tls=0;
const char *tls_cert_path = NULL ;
const char *tls_key_path = NULL;
#ifdef USE_TLS
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
#endif 

void handle_tls_client(int client_fd);
void handle_http_client(int client_fd);

int lua_json(lua_State *L);
void serialize_json(lua_State *L, int index, luaL_Buffer *bj);

typedef struct {
    char filename[MAX_PATH];
    long local_header_offset; 
    int size;
    int cmpr_size;
    int cmpr_method;
} zip_entry_t;

zip_entry_t zip_contents[MAX_FILES];
int zip_entry_cnt = 0;

const unsigned char *extract_file_data(const zip_entry_t *entry, size_t *out_size) {
    if ((entry->cmpr_method != 0) && (dev_mode)) {
        printf("DEBUG: File '%s' is compressed (method %d), skipping\n", 
               entry->filename, entry->cmpr_method);
        return NULL;
    }
    
    const unsigned char *local_header = zip_data + entry->local_header_offset;
    if (memcmp(local_header, "PK\003\004", 4) != 0) {
        if (dev_mode) printf("DEBUG: Invalid local file header for '%s'\n", entry->filename);
        return NULL;
    }
    
    unsigned short local_name_len = *(unsigned short *)(local_header + 26);
    unsigned short local_extra_len = *(unsigned short *)(local_header + 28);
    const unsigned char *file_data = local_header + 30 + local_name_len + local_extra_len;
    
    *out_size = entry->size;
    return file_data;
}

void discover_zip_structure() {
    if (dev_mode){
    printf("DEBUG: Discovering ZIP structure...\n");
    if (zip_size < 22) {
        printf("DEBUG: ZIP too small\n");
        return;
    }}
    
   // search from end
    const unsigned char *eocd = NULL;
    for (long i = zip_size - 22; i >= 0; i--) {
        if (memcmp(zip_data + i, "PK\005\006", 4) == 0) {
            // validate EOCD
            unsigned short comment_len = *(unsigned short *)(zip_data + i + 20);
            if (i + 22 + comment_len == zip_size) {
                eocd = zip_data + i;
                break;
            }
        }
    }
    if (!eocd) {
        if (dev_mode)
        printf("DEBUG: No valid EOCD found in ZIP data\n");
        return;
    }
    
    //OFFSETS ARE RELATIVE TO ZIP START
    unsigned short total_entries = *(unsigned short *)(eocd + 10);
    unsigned int cd_offset = *(unsigned int *)(eocd + 16); 
    if ((cd_offset >= zip_size)) {
        if(dev_mode)
        printf("DEBUG: Central directory offset %u is beyond ZIP size %lu\n", cd_offset, zip_size);
        return;
    }
    const unsigned char *cd_ptr = zip_data + cd_offset; 
    zip_entry_cnt = 0;
    for (int i = 0; i < total_entries && zip_entry_cnt < MAX_FILES; i++) {
        if ((cd_ptr + 46) > (zip_data + zip_size)) {
            if(dev_mode)
            printf("DEBUG: Central directory entry %d extends beyond ZIP\n", i);
            break;
        }
        
        if ((memcmp(cd_ptr, "PK\001\002", 4) != 0)) {
            if(dev_mode){
            printf("DEBUG: Invalid central directory entry signature at entry %d\n", i);
            printf("DEBUG: Found bytes: %02x %02x %02x %02x\n", 
                   cd_ptr[0], cd_ptr[1], cd_ptr[2], cd_ptr[3]);
            break;
            }
        }
        unsigned short cmpr_method = *(unsigned short *)(cd_ptr + 10);
        unsigned int cmpr_size = *(unsigned int *)(cd_ptr + 20);
        unsigned int uncmpr_size = *(unsigned int *)(cd_ptr + 24);
        unsigned short filename_len = *(unsigned short *)(cd_ptr + 28);
        unsigned short extra_len = *(unsigned short *)(cd_ptr + 30);
        unsigned short comment_len = *(unsigned short *)(cd_ptr + 32);
        unsigned int local_header_offset = *(unsigned int *)(cd_ptr + 42); // Relative to ZIP start
        
        if (((cd_ptr + 46 + filename_len) > (zip_data + zip_size))) {
            if (dev_mode)
            printf("DEBUG: Filename extends beyond ZIP for entry %d\n", i);
            break;
        }
        if (filename_len > 0 && filename_len < MAX_PATH) {
            strncpy(zip_contents[zip_entry_cnt].filename, (char *)(cd_ptr + 46), filename_len);
            zip_contents[zip_entry_cnt].filename[filename_len] = '\0';
            zip_contents[zip_entry_cnt].local_header_offset = local_header_offset;
            zip_contents[zip_entry_cnt].size = uncmpr_size;
            zip_contents[zip_entry_cnt].cmpr_size = cmpr_size;
            zip_contents[zip_entry_cnt].cmpr_method = cmpr_method;
            
            //skip entries ending with '/'
            if ((zip_contents[zip_entry_cnt].filename[filename_len - 1] != '/')){
                if (dev_mode)printf("DEBUG: Found: '%s' (size: %u, method: %d, offset: %u)\n", 
                       zip_contents[zip_entry_cnt].filename, uncmpr_size, 
                       cmpr_method, local_header_offset);
                zip_entry_cnt++;
            } else {
                if(dev_mode)
                printf("DEBUG: Skipping directory: '%s'\n", zip_contents[zip_entry_cnt].filename);
            }
        }
        cd_ptr += 46 + filename_len + extra_len + comment_len;
}
}

const zip_entry_t* find_zip_entry(const char *path) {
    for (int i = 0; i < zip_entry_cnt; i++) {
        if (strcmp(zip_contents[i].filename, path) == 0) {
            return &zip_contents[i];
        }
    }
    return NULL;
}

const zip_entry_t* find_best_match(const char *requested_path) {
    const zip_entry_t *entry = find_zip_entry(requested_path);
    if (entry) return entry;
    if (strlen(requested_path) == 0) {
        const char *index_files[] = {"index.html", "index.htm", "default.html", "default.htm"};
        for (int i = 0; i < 4; i++) {
            entry = find_zip_entry(index_files[i]);
            if (entry) return entry;
        }
        for (int i = 0; i < zip_entry_cnt; i++) {
            const char *filename = strrchr(zip_contents[i].filename, '/');
            if (filename) filename++; else filename = zip_contents[i].filename;
            
            if (strcmp(filename, "index.html") == 0 || strcmp(filename, "index.htm") == 0) {
                return &zip_contents[i];
            }
        }
    }
    for (int i = 0; i < zip_entry_cnt; i++) {
        const char *filename = strrchr(zip_contents[i].filename, '/');
        if (filename) filename++; else filename = zip_contents[i].filename;
        
        if (strcmp(filename, requested_path) == 0) return &zip_contents[i];
     } return NULL;
}

const char* guess_content_type(const char *path) {  
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".xml") == 0) return "application/xml";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcmp(ext, ".ico") == 0) return "image/x-icon";
    if (strcmp(ext, ".woff") == 0) return "font/woff";
    if (strcmp(ext, ".woff2") == 0) return "font/woff2";
    if (strcmp(ext, ".ttf") == 0) return "font/ttf";
    if (strcmp(ext, ".otf") == 0) return "font/otf";
    if (strcmp(ext, ".mp4") == 0) return "video/mp4";
    if (strcmp(ext, ".webm") == 0) return "video/webm";
    if (strcmp(ext, ".pdf") == 0) return "application/pdf";
    if (strcmp(ext, ".txt") == 0) return "text/plain";
    if (strcmp(ext, ".wasm") == 0) return "application/wasm";
    
    return "application/octet-stream";
}
int sqlite_query(lua_State *L){
    const char *db_path=luaL_checkstring(L, 1); 
    const char *sql=luaL_checkstring(L, 2);
    sqlite3 *db;
    if (strncmp(db_path, "site/", 5)==0){
        const zip_entry_t *entry = find_zip_entry(db_path);
        if (entry){
            size_t db_size;
            const unsigned char *db_data = extract_file_data(entry, &db_size);
            if(db_data && db_size > 0)
            {
                FILE *fp = fopen("/tmp/macrobean.db", "wb");
                if(fp){
                    fwrite(db_data, 1, db_size, fp);
                    fclose(fp);
                    db_path="/tmp/macrobean.db";
                }
            }
        }
    }
    if(sqlite3_open(db_path, &db)!=SQLITE_OK){
        lua_pushnil(L);
        lua_pushstring(L, sqlite3_errmsg(db));
        return 2;
    }
    char *errmsg = NULL;
    lua_newtable(L); 
    int row_idx = 1;
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)!=SQLITE_OK)  
    {
        lua_pushnil(L);
        lua_pushstring(L, sqlite3_errmsg(db));
        sqlite3_close(db);
        return 2;
    }     
    int num_cols=sqlite3_column_count(stmt);
    while(sqlite3_step(stmt) == SQLITE_ROW){
        lua_newtable(L); 
        for(int i=0;i<num_cols; i++){
            const char *colname = sqlite3_column_name(stmt, i);
            const char *value = (const char *)sqlite3_column_text(stmt,i);
            lua_pushstring(L,value ? value:"");
            lua_setfield(L,-2,colname);
        }
        lua_rawseti(L, -2, row_idx++);

    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 1;
}
int sqlite_exec(lua_State *L){
    const char *db_path=luaL_checkstring(L, 1); 
    const char *sql=luaL_checkstring(L, 2);
    sqlite3 *db;
    char *errmsg = NULL;
    if (strncmp(db_path, "site/", 5)==0){
        const zip_entry_t *entry = find_zip_entry(db_path);
        if (entry){
            size_t db_size;
            const unsigned char *db_data = extract_file_data(entry, &db_size);
            if(db_data && db_size > 0)
            {
                FILE *fp = fopen("/tmp/macrobean.db", "wb");
                if(fp){
                    fwrite(db_data, 1, db_size, fp);
                    fclose(fp);
                    db_path="/tmp/macrobean.db";
                }
            }
        }
    }
    if(sqlite3_open(db_path, &db)!=SQLITE_OK){
        lua_pushnil(L);
        lua_pushstring(L, sqlite3_errmsg(db));
        return 2;
    }
    if(sqlite3_exec(db, sql, NULL, NULL, &errmsg)!=SQLITE_OK){
        lua_pushnil(L);
        lua_pushstring(L, errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(db);
        return 2;
    }
    sqlite3_close(db);
    lua_pushboolean(L,1);
    return 1;
}

void timeout_hook(lua_State *L, lua_Debug *ar){
    (void)ar;
    luaL_error(L, "Execution timed out (sandbox limit reached)");
}
int lua_json(lua_State *L){
    if(!lua_istable(L, 1)){
        lua_pushnil(L);
        lua_pushstring(L, "json() expects a table");
        return 2;
    }
    luaL_Buffer bj;
    luaL_buffinit(L, &bj);
    serialize_json(L, 1, &bj);
    luaL_pushresult(&bj);
    return 1;
}
lua_State* init_lua(void)
{
    lua_State *L = luaL_newstate();
    if(!L) return NULL;
    luaL_openlibs(L);
    if(sandbox_mode)
    lua_sethook(L, timeout_hook, LUA_MASKCOUNT, SANDBOX_LIMIT);
    luaL_requiref(L, "_G", luaopen_base, 1); 
    lua_pop(L,1);
    luaL_requiref(L, LUA_TABLIBNAME, luaopen_table,1);
    lua_pop(L,1);
    luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1); 
    lua_pop(L, 1);
    luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1); 
    lua_pop(L, 1);
    luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1); 
    lua_pop(L, 1);
    luaL_requiref(L, LUA_COLIBNAME, luaopen_coroutine, 1); 
    lua_pop(L, 1);
    if(use_db){
        lua_newtable(L);
        lua_pushcfunction(L, sqlite_query);
        lua_setfield(L , -2, "query");
        lua_pushcfunction(L, sqlite_exec);
        lua_setfield(L,-2,"exec");
        lua_setglobal(L, "db");
    }
    lua_register (L, "json", lua_json);

    lua_pushnil(L); lua_setglobal(L,"io");
    lua_pushnil(L); lua_setglobal(L,"os");
    lua_pushnil(L); lua_setglobal(L,"package");
    lua_pushnil(L); lua_setglobal(L,"debug");

    return L;
}
bool serve_static(int client_fd, const char *url_path, const char *method, const char *body) {
    char clean_path[MAX_PATH];
    if (url_path[0] == '/') {
        snprintf(clean_path, sizeof(clean_path), "%s", url_path + 1);
    } else {
        snprintf(clean_path, sizeof(clean_path), "%s", url_path);
    }

    const zip_entry_t *entry = find_best_match(clean_path);
    if (!entry || !strstr(entry->filename, ".lua")) {
        if (dev_mode) fprintf(stderr, "No static .lua file found for fallback: %s\n", clean_path);
        return false;
    }

    size_t file_size;
    const unsigned char *file_data = extract_file_data(entry, &file_size);
    if (!file_data) {
        if (dev_mode) fprintf(stderr, "Could not extract fallback file: %s\n", clean_path);
        return false;
    }

    lua_State *L = init_lua();
    if (!L) {
        const char *err = "HTTP/1.1 500 Internal Server Error\r\n\r\nLua init failed";
        write(client_fd, err, strlen(err));
        return true;
    }

    lua_newtable(L);
    lua_pushstring(L, url_path);
    lua_setfield(L, -2, "path");
    lua_pushstring(L, method);
    lua_setfield(L, -2, "method");
    if (body) {
        lua_pushstring(L, body);
        lua_setfield(L, -2, "body");
    }
    lua_setglobal(L, "request");

    int status = luaL_loadbuffer(L, (const char *)file_data, file_size, entry->filename);
    if (status == LUA_OK) status = lua_pcall(L, 0, 1, 0);

    if (status == LUA_OK && lua_isstring(L, -1)) {
        const char *result = lua_tostring(L, -1);
        dprintf(client_fd,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
                strlen(result), result);
    } else {
        const char *err = lua_tostring(L, -1);
        dprintf(client_fd,
                "HTTP/1.1 500 Internal Server Error\r\n\r\nStatic Lua Error: %s",
                err ? err : "unknown");
    }

    lua_close(L);
    return true;
}
void serve_path(int client_fd, const char *url_path, const char *method, const char *body) {
    if (strstr(url_path, "..")) {
        const char *err = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid request path";
        write(client_fd, err, strlen(err));
        return;
    }
    if (dev_mode && (strcmp(url_path, "/admin")==0 || strcmp(url_path, "/admin.html")==0)){
        const zip_entry_t *admin = find_zip_entry ("site/admin.html");
        if (!admin) {
            const char *err = "HTTP/1.1 404 Not Found\r\n\r\nsite/admin.html not found in ZIP.";
            write(client_fd, err, strlen(err));
            return;
        }
        size_t size;
        const unsigned char *data = extract_file_data(admin, &size);
        const char *mime = "text/html";
        char header[512];
        snprintf(header, sizeof(header),
    "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %lu\r\n\r\n",
mime, size);
write(client_fd, header, strlen(header));
write(client_fd, data, size);
return;
    }
    char clean_path[MAX_PATH];
    if (url_path[0] == '/') {
        strcpy(clean_path, url_path + 1);
    } else {
        strcpy(clean_path, url_path);
    }
    char *qs_start=strchr(clean_path, '?');
    if(qs_start) *qs_start='\0';
    if(use_lua){
        lua_State *L = init_lua();
        if(!L){
            const char *err = "HTTP/1.1 500 Internal Server Error\r\n\r\nFailed to init Lua";
            write(client_fd,err,strlen(err));
            return;
        }
        lua_newtable(L); 
        lua_pushstring(L, url_path);
        lua_setfield(L,-2,"path");
        lua_pushstring(L, method);
        lua_setfield(L,-2, "method");
        lua_newtable(L);
        char *query_start = strchr(url_path, '?');
        if(query_start && *(query_start+1) != '\0'){
            char *query_dup=strdup(query_start+1);
            if(query_dup){
                char *saveptr = NULL;
                char *pair=strtok(query_dup,"&");
                while(pair){
                char *eq=strchr(pair,'=');
                if(eq){
                    *eq='\0';
                    const char *key=pair;
                    const char *val=eq+1;
                    lua_pushstring(L, val);
                    lua_setfield(L, -2, key);

                } pair = strtok(NULL, "&");
            } 
            free(query_dup);
        }
        }
        lua_setfield(L, -2,"query");
        lua_newtable(L); 
        lua_setfield(L,-2,"headers");
        if(body){
            lua_pushstring(L,body);
            lua_setfield(L,-2,"body");
        }
        lua_setglobal(L,"request");
        // load init.lua if exists in zip
        const zip_entry_t *init_entry=find_zip_entry("site/init.lua");
        if(init_entry){
        size_t init_size = 0;
        const unsigned char *init_code = extract_file_data(init_entry, &init_size);
        if (init_code && init_size > 0){
            int istatus = luaL_loadbuffer(L, (const char*)init_code, init_size, "init.lua");
            if(istatus==LUA_OK){
                istatus=lua_pcall(L,0,0,0);
                if(istatus!=LUA_OK && dev_mode){
                    fprintf(stderr, "init.lua error: %s\n", lua_tostring(L,-1));
                    lua_pop(L,1);
                }
            } else if (dev_mode){
                fprintf(stderr, "failed to load init.lua: %s\n", lua_tostring(L,-1));
                lua_pop(L,1);
            }
        } else if (dev_mode) fprintf(stderr, "falied to extract init.lua from zip\n");
    } else if (dev_mode) fprintf(stderr, "init.lua not found in zip, skipping\n");
    // check dynamic route handler
    lua_getglobal(L, "routes");
    if(lua_istable(L, -1)){
        char routed_path[MAX_PATH];
        snprintf(routed_path, sizeof(routed_path), "/%s", url_path);
        char *qs = strchr(routed_path, '?');
        if(qs) *qs = '\0';
        lua_pushstring(L, routed_path);
        lua_gettable(L,-2);
        if(lua_isfunction(L,-1)){
            if(dev_mode) printf("Matched dynamic route: %s\n", routed_path);
            lua_getglobal(L,"request");
            int rstatus = lua_pcall(L,0,1,0);
            if (rstatus==LUA_OK && lua_isstring(L,-1)){
                const char *result = lua_tostring(L,-1);
                dprintf(client_fd, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s", strlen(result), result);
                lua_pop(L,2);
                lua_close(L);
                return;
            } else {
                const char *err = lua_tostring(L,-1);
                dprintf(client_fd, "HTTP/1.1 500 Internal Server Error\r\n\r\nRoute Error: %s", err?err:"unknown");
                lua_pop(L,2);
                lua_close(L);
                return;
            }
        } lua_pop(L,1); 
    } 
    lua_pop(L,1); 
    char route_key[MAX_PATH];
    strncpy(route_key, url_path, sizeof(route_key));
    char *q = strchr(route_key, '?');
    if (q) *q = '\0';
    
    lua_getglobal(L, "find_route");
    lua_pushstring(L, route_key);
    lua_call(L, 1, 2);
    if(!lua_isfunction(L, -2)){
        if (dev_mode) fprintf(stderr, "No function handler returned for %s\n", route_key);
        lua_pop(L, 2);
        lua_close(L);
        if (serve_static(client_fd, url_path, method, body)) return;
        const char *resp = "HTTP/1.1 404 Not Found\r\n\r\nNo matching route or fallback";
        write(client_fd, resp, strlen(resp));
        return;
    }
    else if (lua_isfunction(L, -2)){
            if(dev_mode) printf("Matched pattern route: %s\n", route_key);
            lua_getglobal(L, "request");
            lua_pushvalue(L, -2);  
            lua_setfield(L, -2, "params");
            lua_pop(L,1);
            lua_remove(L, -1);
            lua_getglobal(L, "routes");
            if(lua_istable(L, -1)) {
                lua_getfield(L, -1, "before");
                if(lua_isfunction(L,-1)){
                    int bstatus = lua_pcall(L,0,1,0);
                    if (bstatus==LUA_OK && lua_isstring(L,-1)){
                        const char *middleware_response = lua_tostring(L, -1);
                        dprintf(client_fd, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
                        strlen(middleware_response), middleware_response);
                        lua_close(L); return;
                    }
                    lua_pop(L,1);
                }else{lua_pop(L,1);
                }
            }
            lua_pop(L,1); 
            int rstatus = lua_pcall(L, 0, 1, 0);
            if(rstatus == LUA_OK && lua_isstring(L,-1)){
                const char *result = lua_tostring(L,-1);
                dprintf(client_fd,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
            strlen(result), result);
            lua_close(L);
            return;
            } else {
                const char *err = lua_tostring(L, -1);
                dprintf(client_fd, "HTTP/1.1 500 Internal Server Error\r\n\r\nPattern route error: %s", err ? err : "unknown");
                lua_close(L);
            return;
            }
        }
        else{
            if (dev_mode) fprintf(stderr, "No function handler returned for %s\n", route_key);
            lua_pop(L, 2); 
        }
    }
    const zip_entry_t *entry = find_best_match(clean_path);
    if (!entry) {
        if (dev_mode)
        fprintf(stderr, "DEBUG: No file found, sending 404\n");
        const char *response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
                              "<html><body><h1>404 Not Found</h1><p>Available files:</p><ul>";
        write(client_fd, response, strlen(response));
        for (int i = 0; i < zip_entry_cnt && i < 10; i++) {
            char file_info[512];
            snprintf(file_info, sizeof(file_info), "<li>%s</li>", zip_contents[i].filename);
            write(client_fd, file_info, strlen(file_info));
        }
        const char *footer = "</ul></body></html>";
        write(client_fd, footer, strlen(footer));
        return;
    }
    size_t file_size;
    const unsigned char *file_data = extract_file_data(entry, &file_size);
    if (!file_data) {
        if(dev_mode)
        printf("DEBUG: Could not extract file data, sending 500\n");
        const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\nCould not extract file";
        write(client_fd, response, strlen(response));
        return;
    }
    
    if(use_lua && strstr(entry->filename,".lua")){
    lua_State *L = init_lua();
       // route handler 
        int status=luaL_loadbuffer(L, (const char*)file_data,file_size,entry->filename);
        if(status==LUA_OK){
            status=lua_pcall(L,0,1,0);
        }
        if(status==LUA_OK && lua_isstring(L,-1)){
            const char *result = lua_tostring(L,-1);
            dprintf(client_fd, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
            strlen(result), result);
        }else{
            const char *err=lua_tostring(L,-1);
            dprintf(client_fd, "HTTP/1.1 500 Internal Server Error\r\n\r\nLua Error: %s", err? err:"unknown");
        }
        lua_close(L);
        return;
    }
    
    const char *mime_type = guess_content_type(entry->filename);
    char header[1024];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %lu\r\n"
             "Cache-Control: public, max-age=3600\r\n"
             "\r\n",
             mime_type, file_size);
    write(client_fd, header, strlen(header));
    write(client_fd, file_data, file_size);
}

int load_zip_from_self(const char *self_path) {
    FILE *fp = fopen(self_path, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open executable file\n"); return 0;
    }
    
    fseek(fp, 0, SEEK_END);
    long total_size = ftell(fp);
    if (total_size < 22) {
        fprintf(stderr, "Error: File too small to contain ZIP data\n");
        fclose(fp);
        return 0;
    }
    const int search_size = 65536;
    long find_start = (total_size > search_size) ? (total_size - search_size) : 0;
    size_t find_length = total_size - find_start;
    
    unsigned char *find_buffer = malloc(find_length);
    if (!find_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(fp);
        return 0;
    }
    
    fseek(fp, find_start, SEEK_SET);
    if (fread(find_buffer,1,find_length, fp)!=find_length) {
        fprintf(stderr, "Error: Could not read find buffer\n");
        free(find_buffer);
        fclose(fp);
        return 0;
    }
    long eocd_offset = -1;
    for (long i =find_length-22;i >= 0;i--) {
        if (memcmp(find_buffer + i, "PK\005\006", 4) == 0) {
            unsigned short comment_len = *(unsigned short *)(find_buffer + i + 20);
            if (find_start + i + 22 + comment_len==total_size) {
                eocd_offset = find_start +i;
                break;
            }
        }
    }
    free(find_buffer);
    if (eocd_offset == -1) {
        fprintf(stderr, "Error: No valid ZIP EOCD found\n");
        fclose(fp);
        return 0;
    }
    unsigned char eocd_data[22];
    fseek(fp, eocd_offset, SEEK_SET);
    if (fread(eocd_data,1,22, fp)!=22) {
        fprintf(stderr, "Error: Could not read EOCD\n");
        fclose(fp);
        return 0;
    }
    unsigned int cd_offset = *(unsigned int *)(eocd_data + 16);
    zip_start_offset = eocd_offset - (eocd_offset - cd_offset);
    for (long test_start = 0; test_start < eocd_offset; test_start++){
        fseek(fp, test_start, SEEK_SET);
        unsigned char sig[4];
        if (fread(sig, 4, 1, fp) == 1){
            if (memcmp(sig, "PK\003\004", 4) == 0){
                long test_cd_absolute = test_start + cd_offset;
                if (test_cd_absolute < eocd_offset){
                fseek(fp, test_cd_absolute, SEEK_SET);
                if (fread(sig, 4,1,fp)==1 && memcmp(sig, "PK\001\002",4) == 0){
                zip_start_offset = test_start;break;}
                }
            }
        }
    }
    
    if (zip_start_offset == -1) {
        fprintf(stderr,"Error: Could not determine ZIP start offset\n");
        fclose(fp);
        return 0;
    }
    zip_size = total_size - zip_start_offset;
    zip_data = malloc(zip_size);
    if (!zip_data){
        fprintf(stderr,"Error: Could not allocate memory for ZIP data\n");
        fclose(fp);
        return 0;
    }
    fseek(fp, zip_start_offset, SEEK_SET);
    if (fread(zip_data,1,zip_size,fp)!=zip_size) {
        fprintf(stderr,"Error: Could not read ZIP data\n");
        free(zip_data);
        zip_data = NULL;
        fclose(fp);return 0;
}
    fclose(fp); discover_zip_structure();return (zip_entry_cnt > 0);
}
char *zip_override_path = NULL;

#ifdef USE_TLS
void init_tls_server(){
const char *pers = "macrobean_tls";
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&srvcert);
        mbedtls_pk_init(&pkey);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*) pers, strlen(pers))!=0){
            fprintf(stderr, "Failed to seed CTR_DRBG\n"); exit(1);
        }
        if(mbedtls_x509_crt_parse_file(&srvcert, tls_cert_path)!=0){
            fprintf(stderr, "Failed to parse cert: %s\n", tls_cert_path); exit(1);
        }
        if(mbedtls_pk_parse_keyfile(&pkey, tls_key_path, NULL, NULL, NULL)!=0){
            fprintf(stderr, "Failed to parse key: %s\n", tls_key_path); exit(1);
        }
        if(mbedtls_ssl_config_defaults(&conf, 
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)!=0){
                        fprintf(stderr, "Failed to set SSL config\n");
                        exit(1);
                    }
                    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
                    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
                    if(mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)!=0){
                        fprintf(stderr, "Failed to set own cert\n");
                        exit(1);
                    }
                    if(mbedtls_ssl_setup(&ssl, &conf)!=0){
                        fprintf(stderr, "Failed to setup SSL\n"); exit(1);
                    }
    }

void handle_tls_client(int client_fd){
    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    if(mbedtls_ssl_handshake(&ssl)!=0){
        if(dev_mode) fprintf(stderr, "TLS handshake failed\n");
        mbedtls_ssl_free(&ssl);
        close(client_fd);
        return;
    }

    char buffer[MAX_REQ] = {0};
    ssize_t total_read = 0, bytes_read = 0;
    while((bytes_read = mbedtls_ssl_read(&ssl, (unsigned char*)buffer + total_read, MAX_REQ - total_read -1))>0){
        total_read += bytes_read;
        buffer[total_read]='\0';
        if (strstr(buffer, "\r\n\r\n")) break;
    }

    char method[16] = {0}, path[MAX_PATH]= {0}, version[16]={0};
    char *body = NULL;
    if (sscanf(buffer, "%15s %1023s %15s", method, path, version) == 3){
        int content_length = 0;
        char *cl = strcasestr(buffer, "Content-Length:");
        if (cl) sscanf(cl, "Content-Length: %d", &content_length);
        char *header_end = strstr(buffer, "\r\n\r\n");
        char *body_start = header_end ? header_end + 4: NULL;
        int body_bytes_read = total_read -(body_start-buffer);
        if (content_length>0){
            body = malloc(content_length+1);
            if (body_start && body_bytes_read >0)
            memcpy(body, body_start, body_bytes_read);

            while(content_length>body_bytes_read){
                ssize_t br = mbedtls_ssl_read(&ssl, (unsigned char*)body + body_bytes_read, content_length-body_bytes_read);
                if (br<=0) break;
                body_bytes_read+=br;
            }
            body[content_length]='\0';
        }
        serve_path(client_fd, path, method, body);
        if (body) free(body);
    }
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    close(client_fd);
}
#endif

void handle_http_client(int client_fd){
    char request[MAX_REQ] = {0};
    ssize_t total_read = 0, bytes_read = 0;
    while ((bytes_read = read(client_fd, request + total_read, MAX_REQ - total_read - 1)) > 0) {
        total_read += bytes_read;
        request[total_read] = '\0';
        if (strstr(request, "\r\n\r\n")) break;
    }

    char method[16] = {0}, path[MAX_PATH] = {0}, version[16] = {0};
    char *body = NULL;
    if (sscanf(request, "%15s %1023s %15s", method, path, version) == 3) {
        int content_length = 0;
        char *cl = strcasestr(request, "Content-Length:");
        if (cl) sscanf(cl, "Content-Length: %d", &content_length);

        char *header_end = strstr(request, "\r\n\r\n");
        char *body_start = header_end ? header_end + 4 : NULL;
        int body_bytes_read = total_read - (body_start - request);

        if (content_length > 0) {
            body = malloc(content_length + 1);
            if (body_start && body_bytes_read > 0)
                memcpy(body, body_start, body_bytes_read);

            while (body_bytes_read < content_length) {
                ssize_t br = read(client_fd, body + body_bytes_read,
                                 content_length - body_bytes_read);
                if (br <= 0) break;
                body_bytes_read += br;
            }
            body[content_length] = '\0';
        }
        serve_path(client_fd, path, method, body);
        if (body) free(body);
    }
    close(client_fd);
}

int main(int argc, char **argv) {
    int port = PORT;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i], "--help")|| !strcmp(argv[i], "-h")){
            printf("Macrobean - Single-binary Web Server\n\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf(" --help, -h       Show this help message\n");
            printf(" --port <number>  Use custom port instead of default (%d)\n",PORT);
            printf(" --dev            Enable dev mode \n");
            printf(" --fork           Enable fork() mode per request\n");
            printf(" --zip <file>     Use external zip file instead of embedded\n");
            printf(" --lua            Enable lua script execution for .lua files (sandboxed)\n");
            printf(" --db             Enable sqlite database for .db files\n");
            printf(" --sandbox        Enable sandboxing\n");
            printf(" --tls            Enable TLS support\n");
            printf(" --cert <file>    Path to TLS certificate (PEM)\n");
            printf(" --key <file>     Path to TLS private key (PEM)\n");
            printf(" --watch          Auto-reload ZIP + DB (dev only)\n");
            printf(" --bundle         Build final .com release\n");
            return 0;
        } else if(!strcmp(argv[i], "--port")) {
            if(i+1<argc) port=atoi(argv[++i]);
        else {fprintf(stderr, "Error: --port requires a number\n");return 1;} }
        else if (!strcmp(argv[i], "--dev")) dev_mode=1;
        else if (!strcmp(argv[i], "--lua")) use_lua=1;
        else if (!strcmp(argv[i], "--db")) use_db=1;
        else if (!strcmp(argv[i], "--sandbox")) sandbox_mode=true;
        else if (!strcmp(argv[i], "--cert") && i+1 < argc) tls_cert_path=argv[++i];
        else if (!strcmp(argv[i], "--key") && i+1 < argc) tls_key_path=argv[++i];  
        else if (!strcmp(argv[i], "--watch")) {
            watch_mode = true;
            dev_mode = true;
        }
        else if (!strcmp(argv[i], "--zip")) 
        {
            if(i+1<argc)
            zip_override_path=argv[++i];
        else {
            fprintf(stderr, "Error: --zip requires a path to a .zip uncompressed file\n");
        }
        }
        else if(!strcmp(argv[i], "--fork")) use_fork=1;
        else
        {
            fprintf(stderr, "Unknown argument: %s\nuse --help to see available options", argv[i]); return 1;
        }
    }
    #ifdef USE_TLS
    if (use_tls){
        if(!tls_cert_path || !tls_key_path)
        {
            if (dev_mode) {
                fprintf(stderr, "[dev] TLS cert/key missisng, falling back to HTTP\n");
                use_tls=false;
            }
            else {
                fprintf(stderr, "TLS enabled but cert/key missing\n");
                exit(1);
            }
        } init_tls_server();
    }
    #endif

    printf("Running Macrobean Server\n");
    if (dev_mode)
    printf("Extracting embedded content...\n");
    if (zip_override_path){
        FILE *fp = fopen(zip_override_path, "rb");
        if(!fp){fprintf(stderr, "Error: Cannot open ZIP: %s\n", zip_override_path);
        return 1;}
        fseek(fp,0,SEEK_END);
        zip_size=ftell(fp);
        rewind(fp);
        zip_data=malloc(zip_size);
        if(!zip_data){
            fprintf(stderr, "Error: not enough memory to load ZIP\n"); 
            fclose(fp); 
            return 1;
        }
        fread(zip_data, 1, zip_size, fp);
        fclose(fp);
       if (dev_mode) fprintf(stderr, "Loaded external ZIP: %s (%zu bytes)\n",zip_override_path,zip_size);
       discover_zip_structure();
    } 
    else {
        if(dev_mode)
        fprintf(stderr, "No external ZIP provided. Falling back to embedded ZIP.\n");
        load_zip_from_self(argv[0]);
    }
    printf("successfully fetched %d files from embedded archive\n", zip_entry_cnt);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {.sin_family = AF_INET,.sin_addr.s_addr = INADDR_ANY,.sin_port = htons(port)};
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        return 1;
    }
    
    if (listen(fd, 10) < 0) {
        perror("listen failed");
        return 1;
    }
    printf("server running on http://localhost:%d\n", port);
    printf("available files:\n");
    for (int i =0; i<zip_entry_cnt;i++) {
        printf("  - %s\n", zip_contents[i].filename);
    } printf("\npress ctrl+c to stop\n\n");
    fd_set readfds;
    int maxfd=fd;
    signal(SIGCHLD, SIG_IGN); // auto reap child
    while(1){
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        int ready=select(fd+1, &readfds, NULL, NULL, NULL);
        if (ready<0)
        {
            if(dev_mode) perror("select()");
            continue;
        }
        if(FD_ISSET(fd, &readfds)){
            int client_fd=accept(fd, NULL, NULL);
            if(client_fd<0) continue;
            if(use_fork){
                pid_t pid = fork();
                if (pid==0){
                    close(fd);
                    if(use_tls) handle_tls_client(client_fd);
                    else handle_http_client(client_fd);
                 _exit(0);
                } else if (pid>0) {
                    close(client_fd);
                
                }
            }
                else { 
                    if (use_tls) handle_tls_client(client_fd);
                    else handle_http_client(client_fd);
                }
            }
        }
    
        if (watch_mode){
            time_t now = time(NULL);
            if(zip_override_path && now - last_zip_mtime >=2){
                struct stat st;
                if(stat(zip_override_path, &st) == 0 && st.st_mtime != last_zip_mtime){
                    fprintf(stderr, "[watch] Reloading zip from disk...\n");
                    FILE *fp = fopen(zip_override_path, "rb");
                    if(fp){
                        fseek(fp, 0, SEEK_END);
                        zip_size = ftell(fp);
                        fseek(fp, 0, SEEK_SET);
                        free(zip_data);
                        zip_data= malloc(zip_size);
                        fread(zip_data, 1, zip_size, fp);
                        fclose(fp);
                        last_zip_mtime = st.st_mtime;
                        discover_zip_structure();
                    }
                }
            }
            if (use_db && now - last_db_reload >=2) {
                const zip_entry_t *db_entry = find_zip_entry("site/data.db");
                if(db_entry){
                    size_t db_size;
                    const unsigned char *db_data = extract_file_data(db_entry, &db_size);
                    if(db_data && db_size>0)
                    {
                        FILE *fp = fopen("/tmp/macrobean.db", "wb");
                        if(fp){
                            fwrite(db_data, 1, db_size, fp);
                            fclose(fp);
                            if(dev_mode)
                            fprintf(stderr, "[watch] Re-extracted site/data.db -> /tmp/macrobean.db\n");
                        }
                    }
                }
                last_db_reload=now;
            }
        }
    #ifdef USE_TLS
    if (use_tls){
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_x509_crt_free(&srvcert);
        mbedtls_pk_free(&pkey);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
    #endif
    if (zip_data) {
        free(zip_data);
    }
    return 0;
}
void serialize_json(lua_State *L, int index, luaL_Buffer *bj){
    if(lua_istable(L, index)){
        int is_array = 1;
        lua_pushnil(L);
        while(lua_next(L, index)){
            if(!lua_isinteger(L, -2)){
                is_array=0;
                lua_pop(L,2);
                break;
            }
            lua_pop(L,1);
        }
        if(is_array){
            luaL_addchar(bj, '[');
            int n=lua_rawlen(L, index);
            for(int i=1;i<=n;i++){
                lua_rawgeti(L, index, i);
                serialize_json(L, lua_gettop(L), bj);
                lua_pop(L, 1);
                if(i<n) luaL_addchar(bj, ',');
            }
            luaL_addchar(bj, ']');
        } else{
            luaL_addchar(bj, '{');
            int first = 1;
            lua_pushnil(L);
            while(lua_next(L, index)){
                if(!first) luaL_addchar(bj, ',');
                first = 0;
                lua_pushvalue(L,-2);
                size_t klen;
                const char *key = lua_tolstring(L, -1, &klen);
                luaL_addchar(bj, '"');
                luaL_addlstring(bj, key, klen);
                luaL_addstring(bj, "\":");
                lua_pop(L,1);
                serialize_json(L, lua_gettop(L), bj);
                lua_pop(L, 1);
            }
            luaL_addchar(bj , '}');
        }
    }else if(lua_isstring(L, index)){
            size_t len;
            const char *s = lua_tolstring(L, index, &len);
            luaL_addchar(bj, '"');
            luaL_addlstring(bj, s, len);
            luaL_addchar(bj, '"');


        } else if(lua_isboolean(L, index)){
            luaL_addstring(bj, lua_toboolean(L, index) ? "true" : "false");
        } else if (lua_isnil(L, index)) {
            luaL_addstring(bj, "null");
        }else if (lua_isnumber(L, index)){
            char num[32];
            snprintf(num, sizeof(num), "%g", lua_tonumber(L, index));
            luaL_addstring(bj, num);
        } else {
            luaL_addstring(bj, "\"<unsupported>\"");
        }
}

