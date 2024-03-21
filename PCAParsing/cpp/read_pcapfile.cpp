#include<iostream>
#include<fstream>
#include<string.h>
#include<dirent.h>
#include<pthread.h>
#include<unistd.h>
#include<set>

#include "headers/parse_pcap_struct.h" // structure of headers
#include "headers/find_unique_ip_adddress.h" // count of Unqiue ip
#include "headers/validate_UserInput.h"
#include "headers/parse_pcap.h"

#define ipV4TypeCheck 8 
#define ipV6TypeCheck 56710
#define ARPPacketTypeCheck 1544
#define checkforTCP 6
#define checkforUDP 17
#define filetype 101
#define consoletype 202
using namespace std;
  
string path_of_source_folder; 
validate_userInput validate_InputObj;

void* Watching_over_Folder(void *arg){ 

      struct dirent *entry_of_directory_provided_by_user; 
      char *quit_t = (char *) arg;
      pthread_detach(pthread_self());
      string file_read_from_directory;

      while(true){

        int count_of_files_in_library = 0;
        char path_of_watch_folder[path_of_source_folder.size()];
        int timer_to_save_cpu_cost_when_idle = 1;

        for(int i = 0; i < path_of_source_folder.size(); i++){
          path_of_watch_folder[i] = path_of_source_folder[i];
        }

        sleep_again:
        DIR *directory_provided_by_user = opendir(path_of_watch_folder);
        
        while((entry_of_directory_provided_by_user = readdir(directory_provided_by_user)) != NULL){ // to check number of files in directory.
            count_of_files_in_library++;
        }

        closedir(directory_provided_by_user);
       
       if(count_of_files_in_library == 2){

            sleep(2 * timer_to_save_cpu_cost_when_idle); // if default, . and .. are available, then no new files are left to be read. 
            timer_to_save_cpu_cost_when_idle++; // time increases twice when noticed that no files are provided by user.

            if(*quit_t == 'q'){
                pthread_exit(NULL); 
             } 

             if(timer_to_save_cpu_cost_when_idle == 100){ // threshold, when reached will go back to 1.
                timer_to_save_cpu_cost_when_idle = 1;
             }

            count_of_files_in_library = 0;
            goto sleep_again; // if no files entered, state would be sleep mode. 
       }

       timer_to_save_cpu_cost_when_idle = 1; // when new file added, timer back to 1. 
  
       directory_provided_by_user = opendir(path_of_watch_folder);
        while ((entry_of_directory_provided_by_user = readdir(directory_provided_by_user)) != NULL) {
          
          file_read_from_directory = entry_of_directory_provided_by_user->d_name;
         // used string, because getting a warning when char type is compared with string literal.
         if(file_read_from_directory == "." || file_read_from_directory == ".." || file_read_from_directory == ".DS_Store"){
          continue;
         }

          Create_csv_to_store_data(entry_of_directory_provided_by_user->d_name);

         char filename_of_pcap[(path_of_source_folder + '/' + entry_of_directory_provided_by_user->d_name).size()];

        for(int i = 0; i < (path_of_source_folder + '/' + entry_of_directory_provided_by_user->d_name).size(); i++){
          filename_of_pcap[i] = (path_of_source_folder + '/' + entry_of_directory_provided_by_user->d_name)[i];
        }

        std::ifstream fileCheck(filename_of_pcap, ios_base::binary);
   
        if(fileCheck && ValidateExtensionOfFile(filename_of_pcap)){ // check extension and existence. 

        storeinCSV<<"S.No"<<","<<"DstMAC"<<","<<"SrcMAC"<<","<<"SrcAd"<<","<<"DstAd"<<","<<"SrcPort"<<","<<"DstPort"<<","<<"PacketLength"<<"\n";
        loggingIn<<INFO<< "File opened successfully." << std::endl;

          ParsingOfPCAPFile(filename_of_pcap);

          
          cout<<"Data is saved successfully."<<endl;
          loggingIn<<INFO<<"Complete file has been read and closed." << std::endl;
    
    }
      else{
         cout<<"File does not exist or the extension of the file is not PCAP.";
         loggingIn<<INFO<< "File does not exist/incorrect extension." <<endl;
    }
      if (remove(filename_of_pcap)== 0) { // deleting file after reading.
        //printf("Deleted successfully"); 
      }
      storeinCSV.close();
    }
      closedir(directory_provided_by_user);
      if(*quit_t == 'q'){ // if pressed q, application will quit.
        pthread_exit(NULL); 
    } 

  }

}

void Initilise_ParsingPcapFile(){

    pthread_t pthread_id; // creating the main thread here. 
    char val = '\0';
    pthread_create(&pthread_id, NULL, &Watching_over_Folder,(void*)&val); // implementing multi threading here.
    //pthread_join(pthread_id, NULL); 
    while(val != 'q'){ // when q entered by user, application exit.
        cin>>val;
    }
    pthread_exit(NULL);
}


int main()
{   
    int print_type_file_or_console;
    
    string path_of_destination_folder;
    cout<<"Path of folder which needs to be watched: ";
    cin>>path_of_source_folder;

    if(validate_InputObj.Check_directory_exists(path_of_source_folder) == false){ // check whether source directory exists or not.
      return 0;
    }

    cout<<"Please provide the path of the destination folder where data would be saved:";
    cin>>path_of_destination_folder;

    if(validate_InputObj.Check_directory_exists(path_of_destination_folder) == false){ // check whether destination directory exists or not. 
      return 0;
     }

    path_of_destination_folder.push_back('/'); // to store files in the folder.
    csv_for_count_of_IP_Address(path_of_destination_folder); // create csv for count of ip address. 

    cout<<"Press 101, if you wish to print in the file."<<endl;
    cout<<"Press 202, if you wish to print on the console."<<endl;
    cout<<"Enter the choice: ";
    cin>>print_type_file_or_console;
    cout<<"Press, 'q' to exit the application."<<endl;

    if(print_type_file_or_console == filetype || print_type_file_or_console == consoletype){
      required_utilities(path_of_destination_folder, print_type_file_or_console);
      Initilise_ParsingPcapFile();

    }
    else{
          cout<<"Wrong choice selected."<<endl;
    }
    return 0;
}