// file to break multiple filters into individual filters {eg  : (len < 250 && (ip.saddr == 192.168.1.9) && (dport in 400,1000)) }, pass each filter to "discrete_filtering.h" and get true or false if packet is valid or not 
// put the value into a string { (T && (T) && (T)) } and return true or false for complete filterString { eg : T} , return T or F for each packet

// necessary header files
#include <cstdio>  
#include <stack>  
#include <queue> 
#include <cctype>
#include <string.h>
#include "common.h"
using namespace std;

class C_packetFilter{ 
    struct ST_filterDependencies st_ftrDep;             // dependency to store the dissected filter string
public:     
    void seperateFilter(string filterString);
    // Accepts a filter string, and then breaks it into discrete filter strings, so that complete filter dissection is done only once.
    
    void findAllFilters(string filter);
    // divide multiple filters into single filters , pass each individual filterString for validity if next character is && , || , )
    
    void getSingleFilter(string &filter_info);
    // check if filter is valid or not then pass to "validate_single_filter" to get T or F for each filter valid for packet
    // 1. single filter is empty  
    
    void removeLeadingAndTrailingSpaces(string &filter_info);
    // remove Leading and training spaces present in string {eg : (      dport in 400,1000      )  -> (dport in 400,1000)}
    
    void evalSuffix(queue<char> &q, stack<char> &s);
    //Suffix expression evaluation
    
    bool findSuffix(string boolFilter);
    //Find the suffix expression corresponding to the expression
    
    int convertBoolToNumber(char c);
    //Convert F and T, convert logical expressions into numbers
    
    int priorityExpression(char c);
    //Find the priority of the expression
    
    void string_to_charArray(string str, char cArr[]);      
    // information which is returned as string are stored in character array here.
    
    void filter_fragmentation(string &filter_info);
    // function which the breaks the single filter string, and stores it in filterVector of struture ST_filterDependencies
    
    bool filter_single_param(vector<st_filter_tokens> brokenArr, C_packet_information &pktInfo);      
    // function which the breaks the single filter string, and checks which type of check is asked in this filter
    
    bool validate_filter(C_packet_information &pktInfo);
    // starting point of the discrete filtering file, which takes input a single filter string (e.g, len < 50) from the 
    // findAllFilters.h file
    
    bool compare_geq(char actVal[], char filVal[], char symbol[]);  
    // checks greater than or equal to in case of string values
    
    bool compare_leq(char actVal[], char filVal[], char symbol[]);  
    // checks less than or equal to in case of string values
    
    bool compare_neq(char filVal[], char actVal[]);         
    // checks not equality in case of string values
    
    bool compare_eq(char filVal[], char actVal[]);          
    // checks equality in case of string values
    
    bool compare_neq_dec(char filVal[], int actualVal);     
    // checks not equality in case of decimal values
    
    bool compare_eq_dec(char filVal[], int actualVal);      
    // checks equality in case of decimal values
    
    bool compare_geq_dec(int actualVal, char filVal[], char symbol[]);      
    // checks for greater than or equal to in case of decimal values
    
    bool compare_leq_dec(int actualVal, char filVal[], char symbol[]);      
    // checks for less than or equal to in case of decimal values
    
};
