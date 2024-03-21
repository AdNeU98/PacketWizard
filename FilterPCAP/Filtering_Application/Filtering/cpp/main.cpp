// Main file to run the application
// necessary header files
#include <iostream>
#include <limits>
#include <fstream>
#include <dirent.h>
#include <time.h>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/time.h>

#include "common.h"
#include "headers/C_pcapWriter.h"
#include "headers/C_packetParser.h"
#include "headers/C_packetFilter.h"
using namespace std;

// objects for various classes
C_packet_information packetInfo;
C_packetParser parser_object;
C_packetFilter filter_object;
C_pcapWriter output_object;
int packet_count = 0;
char*global_hdr;

// for each file (.pcap), every packet is parsed and read. Packet information is stored and passed to filtering module. 
// if filters are matched, then packet is dumped. Individually parsing each packet using this function
void parsing_rawPackets(string filename_of_pcap_file, string output_directory){ 
    //filename, output dir and filter info are passed as arguments.
    ifstream pcap_file(filename_of_pcap_file);
    
    if(pcap_file.is_open()){
        packet_count++;
        pcap_file.seekg(0, ios::end);
        int end = pcap_file.tellg();
        
        pcap_file.seekg(0, ios::beg);
                
        if(packet_count == 1){
            global_hdr = new char[SIZE_GLOBAL_HEADER];
            pcap_file.read(global_hdr, SIZE_GLOBAL_HEADER); // Global header is read here.
            output_object.writeGlobalHeader(global_hdr);
        }
        pcap_file.seekg(SIZE_GLOBAL_HEADER, ios::beg);
        int begin = pcap_file.tellg();
        
        // 1. Extract each individual packet one by one
        // 2. Do the work related to each individual packet
        
        // Individual packet has 2 things:
        // 1. Packet Header (16 bytes)
        // 2. Payload (Maximum 1500 bytes)
        
        ST_PacketHeader* pkt_hdr;
        
        char*packet_header;
        packet_header = new char[SIZE_PACKET_HEADER];
        
        char*payload;
        payload = new char[MAX_PACKET_SIZE_ALLOWED]; // maximum length of packet, 1500.
        
        while(begin < end){
            
            pcap_file.read(packet_header, SIZE_PACKET_HEADER);
            pkt_hdr = (ST_PacketHeader*)packet_header;
            pcap_file.read(payload, pkt_hdr->incl_len); // Packet header is read here.
            
            timeval timestamp;
            
            const char* beg = payload;
            const char* end = payload + pkt_hdr->incl_len;
            
            uint8_t*PayL = new uint8_t[pkt_hdr->incl_len];
            
            size_t i = 0;
            for (; beg != end; ++beg, ++i){
                PayL[i] = (uint8_t)(*beg);
            }
            
            packetInfo.reset();
            
            //information for the raw packet which needs to be send to get the packet parse.
            timestamp.tv_sec = pkt_hdr->ts_sec;
            timestamp.tv_usec = pkt_hdr->ts_usec;
            
            //information is send to third party application, and packet is parsed.
            if(parser_object.single_packet_parser(PayL, pkt_hdr->incl_len, timestamp,packetInfo)){
                //read single filter strings and check if filter is true for that packet
                if(filter_object.validate_filter(packetInfo)){ // if filters get matched then, packet is saved.
                    //filters get matched then, packet is saved.
                    output_object.output_dump(packet_header, pkt_hdr->incl_len, payload);
                }    
            }
            
            if(begin == -1){
                break;
            }
            
            delete[] (PayL);
            
            begin = pcap_file.tellg();            
        }
        delete[] (packet_header);
        delete[] (payload);
    }
    pcap_file.close();
}

// check if Directory Exists or not ; return true if exists , else return false
bool checkDirectoryExists(const char *path){
    DIR *dir = opendir(path);
    if(dir){
        closedir(dir);
        return true;
    }else{
        // cout << "Directory doesn't exist"<<endl;
        return false;
    }
}

// checks if path is file or not ; return true if file , else return false (for directory)
int is_file(const char *path){
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

// check if file exists or not ; return true if exists , else return false (to check if output file is created after complete execution of the directory)
bool doesFileExist(const string& filename) {
    ifstream ifile(filename.c_str());
    if(ifile.is_open()){
        ifile.close();
        return true;
    }
    return false;
}

// find out the filepath for all the files present in the directory (also reads files present in directory of directory) 
void listFilesRecursively(string basePath, string output_directory){
    
    string path = basePath;
    struct dirent *dp;
    DIR *dir = opendir(basePath.c_str());
    
    // Unable to open directory stream
    if (!dir)
        return;
    while ((dp = readdir(dir)) != NULL){
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0 && strcmp(dp->d_name, ".DS_Store") != 0){  // not hidden files
            string filepath = basePath + "/" + dp->d_name;
            int length = filepath.size();
            // reads only .pcap files
            if(is_file(filepath.c_str()) == 1 && tolower(filepath[length-5]) == '.' && tolower(filepath[length-4]) == 'p' && tolower(filepath[length-3]) == 'c' && tolower(filepath[length-2]) == 'a' && tolower(filepath[length-1] =='p'))
                // send file by file to parse each packet
                parsing_rawPackets(filepath, output_directory);
            // Construct new path from our base path
            path = basePath;
            path = path + "/" +dp->d_name;
            listFilesRecursively(path,output_directory);
        }
    }
    closedir(dir);
}

// check if user has entered filterString with balanced paranthesis ; returns true if balanced , else returns false
bool checkBalanced(string str){
    stack<char> s;
    int i=0;
    
    while(str[i] != '\0'){
        if(str[i] == '('){
            s.push(str[i]);
        }else if(str[i]==')'){
            if(!s.empty())
                s.pop();
            else
                return false;
        }
        i++;
    }
    return s.empty();
}

// checks for valid filterString 
// 1. filterString not empty 2. paranthesis balanced 3. contains any illegal character 4. if  .. present in ips etc 
bool filterValidation(ST_UserInputs &st_userinputs){
    
    if(st_userinputs.filterStr.size()>0){
        if(checkBalanced(st_userinputs.filterStr)){
            
            bool checkValidation = true;
            
            for(int i=0;i < st_userinputs.filterStr.size();i++){
                if ((st_userinputs.filterStr[i] >= 65 && st_userinputs.filterStr[i] <= 90) || (st_userinputs.filterStr[i] >= 97 && st_userinputs.filterStr[i] <= 122) ||
                    (st_userinputs.filterStr[i] >= 48 && st_userinputs.filterStr[i] <= 57) ||
                    (st_userinputs.filterStr[i] == ' ' || st_userinputs.filterStr[i] == '(' || st_userinputs.filterStr[i] == ')' || st_userinputs.filterStr[i] == '.' ||st_userinputs.filterStr[i] == ':' || st_userinputs.filterStr[i] == '='|| st_userinputs.filterStr[i] == '&' || st_userinputs.filterStr[i] == '|' ||st_userinputs.filterStr[i] == '!'  || st_userinputs.filterStr[i] == '>' ||st_userinputs.filterStr[i] == '<' ||st_userinputs.filterStr[i] == ',')){
                    if((st_userinputs.filterStr[i] == '.' && st_userinputs.filterStr[i+1] == '.') || (st_userinputs.filterStr[i] == ':' && st_userinputs.filterStr[i+1] ==':')){
                        checkValidation = false;
                        cout<< "Invalid Filter provided : Invalid .. or :: present \n";
                        break;
                    }else
                        checkValidation =true ;
                }else{
                    cout<<"Invalid Filter provided : undefined character "<<st_userinputs.filterStr[i]<<" present\n";
                    checkValidation = false;
                    break;
                }
            }
            if(!checkValidation){
                return false;
            }else{
                return true;
            }
        }else{
            cout<< "Invalid Filter provided : paranthesis mismatch\n";
            return false;
        }
    }else{
        cout << "Invalid Filter provided : Filter String empty\n";
        return false;
    }
}

// provides all filters and there correct acceptable format on console
void filterMenu(){
    cout << "Various Filter formats -> \n";
    cout << "(ip.saddr == a.b.c.d)  ;   (ip.saddr == a:b:c:d:e:f:g:h)\n";
    cout << "(ip.daddr == a.b.c.d)  ;   (ip.daddr == a:b:c:d:e:f:g:h)\n";
    cout << "(ip.addr == a.b.c.d)  ;   (ip.addr == a:b:c:d:e:f:g:h)\n";
    cout << "(len == a)  ;   (len != a)   ;   (len >= a)   ;   (len <= a)   ;   (len > a)   ;   (len < a)   ;   (len in a,b)\n";
    cout << "(smac == a.b.c.d.e.f)  ;   (smac != a.b.c.d.e.f)\n";
    cout << "(dmac == a.b.c.d.e.f)  ;   (dmac != a.b.c.d.e.f)\n";
    cout << "(mac == a.b.c.d.e.f)  ;   (mac != a.b.c.d.e.f)\n";
    cout << "(ether_type == a)  ;   (ether_type != a)\n";
    cout << "(ip.saddr != a.b.c.d)  ;   (ip.saddr != a.b.c.d.e.f.g.h)\n";
    cout << "(ip.daddr != a.b.c.d)  ;   (ip.daddr != a.b.c.d.e.f.g.h)\n";
    cout << "(ip.addr != a.b.c.d)  ;   (ip.addr != a.b.c.d.e.f.g.h)\n";
    cout << "(protocol == a)  ;   (protocol != a)\n";
    cout << "(sport == a)  ;   (sport != a)   ;   (sport >= a)   ;   (sport <= a)   ;   (sport > a)   ;   (sport < a)   ;   (sport in a,b)\n";
    cout << "(dport == a)  ;   (dport != a)   ;   (dport >= a)   ;   (dport <= a)   ;   (dport > a)   ;   (dport < a)   ;   (dport in a,b)\n";
    cout << "(port == a)  ;   (port != a)   ;   (port >= a)   ;   (port <= a)   ;   (port > a)   ;   (port < a)   ;   (port in a,b)\n";
    cout << "(tcp_flags == a)  ;   (tcp_flags != a)\n";
    cout << endl;
}   

int main()
{
    filterMenu();
    time_t start = 0, end;
    ST_UserInputs st_userinputs;
    string ch;
    cout <<"Want to give input through console , Type [C/c]\n";
    cout <<"Want to give input through File , Type [F/f]\n";
    cout <<"Enter your choice : ";
    
    cin >> ch;
    cout << endl;
    // user want to enter via console
    if(ch == "C" || ch == "c"){
        cout << "Enter input directory : ";
        cin >> st_userinputs.inputDir;
        // input directory exists then chcek for output directory and then filter string
        if(checkDirectoryExists(st_userinputs.inputDir.c_str())){
            cout << "Enter output directory : ";
            cin >> st_userinputs.outputDir;
            if(checkDirectoryExists(st_userinputs.outputDir.c_str())){
                output_object.openOutputDirectory(st_userinputs.outputDir);
                cout << "Provide filters in desired format :\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                getline(cin,st_userinputs.filterStr);
                
                if((st_userinputs.filterStr[0] != '(' && st_userinputs.filterStr[st_userinputs.filterStr.length()-1] != ')')){
                    cout<<"Filter not in correct format"<<endl;
                    return 0;
                }
                // filter string validation
                time(&start);
                if(filterValidation(st_userinputs)){
                    filter_object.seperateFilter(st_userinputs.filterStr);
                    listFilesRecursively(st_userinputs.inputDir,st_userinputs.outputDir);
                }
                output_object.closeOutputDirectory();
                delete[](global_hdr);
                // after complete directory transaction if output_dump file is created
                cout <<"Output_dump.pcap created in provided directory according to provided filters"<<endl;
            }else{
                cout << "Output Directory doesn't exist"<<endl;
            }
            time(&end);
            double time_taken = double(end - start);
            // cout << "Time taken by program is : " << fixed << time_taken << setprecision(10);
            // cout << " sec " << endl;
        }else{
            cout << "Input Directory doesn't exist"<<endl;
        }
    }// user want to enter via file
    else if(ch == "F" || ch == "f"){
        string fileInputpath;
        cout << "Format of FilterInputFile :\n"<<"First line InputDirectory\n";
        cout<<"Second line OutputDirectory\n"<<"Third line FilterString\n";
        cout<<endl;
        
        // user enters directory in which inputfile will be created for file input
        cout << "Enter path of inputFile :\n";
        cin >> fileInputpath;
        
        // input directory exists then chcek for output directory and then filter string
        if(doesFileExist(fileInputpath.c_str())){
            
            string fileInputData;
            //.txt validation
            int length = fileInputpath.size();
            if(tolower(fileInputpath[length-4]) == '.' && tolower(fileInputpath[length-3]) == 't' && tolower(fileInputpath[length-2]) == 'x' && tolower(fileInputpath[length-1]) == 't'){
                ifstream inputFile (fileInputpath);
                getline(inputFile, fileInputData);
                
                if(checkDirectoryExists(fileInputData.c_str())){
                    st_userinputs.inputDir = fileInputData ;
                    getline(inputFile, fileInputData);
                    if(checkDirectoryExists(fileInputData.c_str())){
                        st_userinputs.outputDir = fileInputData;
                        output_object.openOutputDirectory(st_userinputs.outputDir);
                        getline(inputFile, fileInputData);
                        st_userinputs.filterStr = fileInputData;
                        if((st_userinputs.filterStr[0] != '(' && st_userinputs.filterStr[st_userinputs.filterStr.length()-1] != ')')){
                            cout<<"Filter not in correct format"<<endl;
                            return 0;
                        }
                        // filter string validation
                        time(&start);
                        if(filterValidation(st_userinputs)){
                            filter_object.seperateFilter(st_userinputs.filterStr);
                            listFilesRecursively(st_userinputs.inputDir, st_userinputs.outputDir);
                        }
                    }else{
                        cout << "Output Directory doesn't exist"<<endl;
                    }
                    time(&end);
                    double time_taken = double(end - start);
                    cout << "Time taken by program is : " << fixed << time_taken << setprecision(10);
                    cout << " sec " << endl;
                }else{
                    cout << "Input Directory doesn't exist"<<endl;
                }
                output_object.closeOutputDirectory();
                delete[] (global_hdr);
                // after complete directory transaction if output_dump file is created
                cout <<"Output_dump.pcap created in provided directory according to provided filters"<<endl;
                inputFile.close(); 
            }else{
                cout << "Please enter .txt file in provided format\n";
            }
            
        }else{
            cout << "No such file exists at provided path \n";
        }
    }else{
        cout << "Please Enter a valid choice\n";
    }
    return 0;
}
