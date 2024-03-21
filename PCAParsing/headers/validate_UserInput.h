#include <iostream>
#include <dirent.h>

using namespace std;

class validate_userInput{

  public:

    bool Check_directory_exists(string path_for_checking_exist_or_not){ 
    // checking whether directory exists or not.
    struct dirent *entry;
    char path_of_directory_check_exist_or_not[path_for_checking_exist_or_not.size()];
    //char path_of_destination_folder_exists[path_of_destination_folder.size()];

    for(int i = 0; i < path_for_checking_exist_or_not.size(); i++){
        path_of_directory_check_exist_or_not[i] = path_for_checking_exist_or_not[i];
    }

    DIR *directory_path = opendir(path_of_directory_check_exist_or_not);

    if (directory_path == NULL) {
       cout<<"Directory does not exist which the user has provided.";
        return false;   
    }

    closedir(directory_path); 
    return true;
    }
};

