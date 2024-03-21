// file to break multiple filters into individual filters {eg  : (len < 250 && (ip.saddr == 192.168.1.9) && (dport in 400,1000)) }, pass each filter to "C_packetFilter.h" and get true or false if packet is valid or not 
// put the value into a string { (T && (T) && (T)) } and return true or false for complete filterString { eg : T} , return T or F for each packet

// necessary header files
#include <iostream>
#include <cstdio>   
#include "headers/C_packetFilter.h"
#include <vector>
using namespace std;

// Accepts a filter string, and then breaks it into discrete filter strings, so that complete filter dissection is done only once.
void C_packetFilter::seperateFilter(string filterString){
    findAllFilters(filterString);
    
    if(st_ftrDep.filterVector.size() == 0){
        cout<<"No filter provided."<<endl;
        exit(1);
    }
    
}

void C_packetFilter::string_to_charArray(string str, char cArr[]){ // information which is returned as string are stored in character array here.
    int iterator_copy_string_to_charArray = 0;
    while(str[ iterator_copy_string_to_charArray ] != '\0'){
        cArr[ iterator_copy_string_to_charArray ] = str[iterator_copy_string_to_charArray];
        iterator_copy_string_to_charArray++;
    }
    cArr[ iterator_copy_string_to_charArray ] = '\0';
    return;
}

// checks for less than or equal to in case of decimal values
bool C_packetFilter::compare_leq_dec(int actualVal, char filVal[], char symbol[]){
    int filterVal = atoi(filVal);
    
    if(strcmp(symbol, "<=") == 0)
        return (actualVal <= filterVal);
    else if(strcmp(symbol, "<") == 0)
        return (actualVal < filterVal);
    else{
        return false;
    }
}

// checks for greater than or equal to in case of decimal values
bool C_packetFilter::compare_geq_dec(int actualVal, char filVal[], char symbol[]){
    int filterVal = atoi(filVal);
    
    // if actual packet value is greater than or equal to filter value
    if(strcmp(symbol, ">=") == 0)
        return (actualVal >= filterVal);
    else if(strcmp(symbol, ">") == 0)
        return (actualVal > filterVal);
    else{
        return false;
    }
}

// checks equality in case of decimal values
bool C_packetFilter::compare_eq_dec(char filVal[], int actualVal){
    int filterVal = atoi(filVal);
    bool ans = (filterVal == actualVal);
    return (ans == true);
}

// checks not equality in case of decimal values
bool C_packetFilter::compare_neq_dec(char filVal[], int actualVal){
    int filterVal = atoi(filVal);
    bool ans = (filterVal == actualVal);
    return (ans != true);
}

// checks equality in case of string values
bool C_packetFilter::compare_eq(char filVal[], char actVal[]){
    int ans = strcmp(filVal, actVal);
    return (ans == 0);
}

// checks not equality in case of string values
bool C_packetFilter::compare_neq(char filVal[], char actVal[]){
    int ans = strcmp(filVal, actVal);
    return (ans != 0);
}

// checks less than or equal to in case of string values
bool C_packetFilter::compare_leq(char actVal[], char filVal[], char symbol[]){
    int actualVal = atoi(actVal);
    int filterVal = atoi(filVal);
    
    // if actual packet value is less than or equal to filter value
    if(strcmp(symbol, "<=") == 0)
        return (actualVal <= filterVal);
    else if(strcmp(symbol, "<") == 0)
        return (actualVal < filterVal);
    else{
        return false;
    }
}

// checks greater than or equal to in case of string values
bool C_packetFilter::compare_geq(char actVal[], char filVal[], char symbol[]){
    int actualVal = atoi(actVal);
    int filterVal = atoi(filVal);
    
    // if actual packet value is greater than or equal to filter value
    if(strcmp(symbol, ">=") == 0)
        return (actualVal >= filterVal);
    else if(strcmp(symbol, ">") == 0)
        return (actualVal > filterVal);
    else{
        return false;
    }
}

// function which the breaks the single filter string, and checks which type of check is asked in this filter
bool C_packetFilter::filter_single_param(vector<st_filter_tokens> brokenArr, C_packet_information &pktInfo){
    // breaking the single filter string to find and apply the respective check provided in it
    
    if(strcmp(brokenArr[0].filter_tokens, "len") == 0){
        // checks the length field
        
        // len > 86
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq_dec(brokenArr[2].filter_tokens, pktInfo.packet_length);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq_dec(brokenArr[2].filter_tokens, pktInfo.packet_length);
        }
        else if((strcmp(brokenArr[1].filter_tokens, ">=") == 0) or (strcmp(brokenArr[1].filter_tokens, ">") == 0)){
            return compare_geq_dec(pktInfo.packet_length, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens);
        }
        else if((strcmp(brokenArr[1].filter_tokens, "<=") == 0) or (strcmp(brokenArr[1].filter_tokens, "<") == 0)){
            return compare_leq_dec(pktInfo.packet_length, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "in") == 0){
            char*part1 = strtok(brokenArr[2].filter_tokens, ",");
            char*part2 = strtok(NULL, ",");
            char gEq[] = ">=";
            char lEq[] = "<=";
            return (compare_geq_dec(pktInfo.packet_length, part1, gEq) && compare_leq_dec(pktInfo.packet_length, part2, lEq));
        }
        else{
            return false;
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "smac") == 0){
        // checks the source mac address field
        
        // smac == 19:c8:12:23:f4:69
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq(brokenArr[2].filter_tokens, pktInfo.source_macAddress);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq(brokenArr[2].filter_tokens, pktInfo.source_macAddress);
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "dmac") == 0){
        // checks the destination mac address field
        
        // dmac == 19:c8:12:23:f4:69
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq(brokenArr[2].filter_tokens, pktInfo.destination_macAddress);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq(brokenArr[2].filter_tokens, pktInfo.destination_macAddress);
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "mac") == 0){
        // checks the mac address field, whih can be either source mac or destination mac
        
        // mac == 19:c8:12:23:f4:69
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return (compare_eq(brokenArr[2].filter_tokens, pktInfo.source_macAddress) || compare_eq(brokenArr[2].filter_tokens, pktInfo.destination_macAddress));
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return (compare_neq(brokenArr[2].filter_tokens, pktInfo.source_macAddress) || compare_neq(brokenArr[2].filter_tokens, pktInfo.destination_macAddress));
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "ether_type") == 0){
        // checks the ethernet_type field, which tells us that what protocol is used on the ip layer (IPV4, IPV6, ARP, etc)
        
        // ether_type == 2048
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq_dec(brokenArr[2].filter_tokens, pktInfo.ethernet_type);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq_dec(brokenArr[2].filter_tokens, pktInfo.ethernet_type);
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "ip.saddr") == 0){
        // checks the source ip address field, which can be either IPV4 or IPV6 type
        
        // ip.saddr == 192.168.1.9
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq(brokenArr[2].filter_tokens, pktInfo.source_ipAddress);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq(brokenArr[2].filter_tokens, pktInfo.source_ipAddress);
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "ip.daddr") == 0){
        // checks the destination ip address field, which can be either IPV4 or IPV6 type
        
        // ip.daddr == 192.168.1.9
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq(brokenArr[2].filter_tokens, pktInfo.destination_ipAddress);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq(brokenArr[2].filter_tokens, pktInfo.destination_ipAddress);
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "ip.addr") == 0){
        // checks the ip address (source or destination both) field, which can be either IPV4 or IPV6 type
        
        // ip.addr == 192.168.1.9
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return (compare_eq(brokenArr[2].filter_tokens, pktInfo.source_ipAddress) || compare_eq(brokenArr[2].filter_tokens, pktInfo.destination_ipAddress));
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return (compare_neq(brokenArr[2].filter_tokens, pktInfo.source_ipAddress) || compare_neq(brokenArr[2].filter_tokens, pktInfo.destination_ipAddress));
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "protocol") == 0){
        // checks for the protocol, whether TCP, UDP, etc
        
        // protocol == TCP
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq(brokenArr[2].filter_tokens, pktInfo.protocol);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq(brokenArr[2].filter_tokens, pktInfo.protocol);
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "sport") == 0){
        //checks for the source port used by the packet
        
        // sport == 29877
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq_dec(brokenArr[2].filter_tokens, pktInfo.source_port);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq_dec(brokenArr[2].filter_tokens, pktInfo.source_port);
        }
        else if((strcmp(brokenArr[1].filter_tokens, ">=") == 0) or (strcmp(brokenArr[1].filter_tokens, ">") == 0)){
            return compare_geq_dec(pktInfo.source_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens);
        }
        else if((strcmp(brokenArr[1].filter_tokens, "<=") == 0) or (strcmp(brokenArr[1].filter_tokens, "<") == 0)){
            return compare_leq_dec(pktInfo.source_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "in") == 0){
            char*part1 = strtok(brokenArr[2].filter_tokens, ",");
            char*part2 = strtok(NULL, ",");
            char gEq[] = ">=";
            char lEq[] = "<=";
            
            return (compare_geq_dec(pktInfo.source_port, part1, gEq) && compare_leq_dec(pktInfo.source_port, part2, lEq));
        }
        else{
            return false;
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "dport") == 0){
        //checks for the destination port set for the packet
        
        // dport == 443
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq_dec(brokenArr[2].filter_tokens, pktInfo.destination_port);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq_dec(brokenArr[2].filter_tokens, pktInfo.destination_port);
        }
        else if((strcmp(brokenArr[1].filter_tokens, ">=") == 0) or (strcmp(brokenArr[1].filter_tokens, ">") == 0)){
            return compare_geq_dec(pktInfo.destination_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens);
        }
        else if((strcmp(brokenArr[1].filter_tokens, "<=") == 0) or (strcmp(brokenArr[1].filter_tokens, "<") == 0)){
            return compare_leq_dec(pktInfo.destination_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "in") == 0){
            char*part1 = strtok(brokenArr[2].filter_tokens, ",");
            char*part2 = strtok(NULL, ",");
            char gEq[] = ">=";
            char lEq[] = "<=";
            return (compare_geq_dec(pktInfo.destination_port, part1, gEq) && compare_leq_dec(pktInfo.destination_port, part2, lEq));
        }
        else{
            return false;
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "port") == 0){
        //checks for the port (source or destination) in the packet
        
        // port == 443
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return (compare_eq_dec(brokenArr[2].filter_tokens, pktInfo.source_port) || compare_eq_dec(brokenArr[2].filter_tokens, pktInfo.destination_port));
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return (compare_neq_dec(brokenArr[2].filter_tokens, pktInfo.source_port) || compare_neq_dec(brokenArr[2].filter_tokens, pktInfo.destination_port));
        }
        else if((strcmp(brokenArr[1].filter_tokens, ">=") == 0) or (strcmp(brokenArr[1].filter_tokens, ">") == 0)){
            return (compare_geq_dec(pktInfo.source_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens) || compare_geq_dec(pktInfo.destination_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens));
        }
        else if((strcmp(brokenArr[1].filter_tokens, "<=") == 0) or (strcmp(brokenArr[1].filter_tokens, "<") == 0)){
            return (compare_leq_dec(pktInfo.source_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens) || compare_leq_dec(pktInfo.destination_port, brokenArr[2].filter_tokens, brokenArr[1].filter_tokens));
        }
        else if(strcmp(brokenArr[1].filter_tokens, "in") == 0){
            char*part1 = strtok(brokenArr[2].filter_tokens, ",");
            char*part2 = strtok(NULL, ",");
            char gEq[] = ">=";
            char lEq[] = "<=";
            return (compare_geq_dec(pktInfo.source_port, part1, gEq) && compare_leq_dec(pktInfo.source_port, part2, lEq)) || (compare_geq_dec(pktInfo.destination_port, part1, gEq) && compare_leq_dec(pktInfo.destination_port, part2, lEq));
        }
        else{
            return false;
        }
    }
    else if(strcmp(brokenArr[0].filter_tokens, "tcp_flags") == 0){
        // checks for the flag present in the packet
        
        // tcp_flags == FIN
        if(strcmp(brokenArr[1].filter_tokens, "==") == 0){
            return compare_eq(brokenArr[2].filter_tokens, pktInfo.tcp_flags);
        }
        else if(strcmp(brokenArr[1].filter_tokens, "!=") == 0){
            return compare_neq(brokenArr[2].filter_tokens, pktInfo.tcp_flags);
        }
    }
    else{
        // if some unknown property is used which is not according to the criteria, then an error message is shown and false is returned
        cout<<"Wrong Filter !!! Write according to the criteria"<<endl;
        exit(1);
    }
    
    return false;
}
// starting point of the discrete filtering file, which takes input a single filter string (e.g, len < 50)from the findAllFilters.h file
bool C_packetFilter::validate_filter(C_packet_information &pktInfo){
    char ch ;
    for(int i=0;i<st_ftrDep.filterVector.size();i++){
        // if true then replace filterString with 'T' else with 'F'
        if(filter_single_param(st_ftrDep.filterVector[i], pktInfo)){
            ch = 'T';
        }else{
            ch = 'F';
        }  
        st_ftrDep.boolFilter[st_ftrDep.pos[i]] = ch;
    }
    // boolFilter = (T && (T) && (T))
    // create boolFilter and finally return true or false , if true dump packet
    return (findSuffix(st_ftrDep.boolFilter));
}


int C_packetFilter::priorityExpression(char c) {//Find the priority of the expression
    int ch;
    if (c == '(') ch=4;
    if (c == '!') ch=3;
    if (c == '&') ch=2;
    if (c == '|') ch=1;
    
    return ch;
}

int C_packetFilter::convertBoolToNumber(char c) {//Convert F and T, convert logical expressions into numbers
    if (c == 'F') return 0;
    else return 1;
}

bool C_packetFilter::findSuffix(string boolFilterString) {//Find the suffix expression corresponding to the expression
    stack<char> s;
    queue<char> q; //Save suffix expression
    
    //Initialize the stack
    while (s.size()) {
        s.pop();
    }
    
    // Manually remove spaces in the string
    for (int i = 0; i<boolFilterString.size(); i++) {
        if (boolFilterString[i] != ' ') {//Remove spaces
            //If you encounter a logical expression, add it directly to the queue and use the queue to put the suffix expression
            if (boolFilterString[i] == 'F' || boolFilterString[i] == 'T') q.push(boolFilterString[i]);
            else if (boolFilterString[i] =='!'&&s.size() && s.top() =='!') {//Encountered two consecutive! ! Offset, directly! Unstack
                s.pop();
            }
            else if (!s.size()) s.push(boolFilterString[i]); //If the stack is empty, enter the stack directly when encountering a logical symbol
            else if (boolFilterString[i] ==')') {//If it is a right parenthesis, pop up all operators before the left parenthesis and add them to the queue
                while (s.top() != '(') {
                    q.push(s.top());
                    s.pop();
                }
                s.pop();
                continue;
            }
            else if (priorityExpression(s.top()) == 4 || (priorityExpression(boolFilterString[i])>priorityExpression(s.top()))) s.push(boolFilterString[i]); //Left parenthesis takes precedence The highest level, the lowest priority after stacking,
            else if (priorityExpression(s.top()) != 4 && priorityExpression(boolFilterString[i]) <= priorityExpression(s.top())) {
                q.push(s.top());
                s.pop(); //If the operator encountered is not as high as the operator on the top of the stack, the operator on the top of the stack is added to the queue and loops continuously
                while (s.size() && priorityExpression(s.top()) != 4 && priorityExpression(boolFilterString[i]) <= priorityExpression(s.top())) {//The pop-up is not lower than c[i] priority Operation
                    q.push(s.top());
                    s.pop();
                }
                s.push(boolFilterString[i]); //Add the current operator to the queue
            }
        }
    }
    //Finally, all operators are added to the stack
    while (s.size()) {
        q.push(s.top());
        s.pop();
    }
    
    evalSuffix(q, s);
    bool flag_to_check_packet_filter = (s.top() == 'T');
    return flag_to_check_packet_filter;
}

void C_packetFilter::evalSuffix(queue<char> &q, stack<char> &s) {//Suffix expression evaluation
    bool r = 1;
    char x, y;
    while (q.size()) {
        // If an operand is encountered, the operand is put on the stack and the queue is dequeued
        if (q.front() == 'T' || q.front() == 'F') {
            s.push(q.front());
            q.pop();
        }
        // When encountering an operator, pop the top two elements of the stack, perform logical operations, and push the result into the stack
        else {
            // logical AND operation
            if (q.front() == '&') {
                x = s.top();
                s.pop();
                if(!s.empty()){
                    y = s.top();
                    s.pop();
                    r = convertBoolToNumber(x) && convertBoolToNumber(y);
                    if (r == 1)
                        s.push('T');
                    else
                        s.push('F');
                }else{
                    cout<<"Invalid Filter Provided\n";
                    exit(1);
                }
            }else if (q.front() == '|') {
                // logical OR operation
                x = s.top();
                s.pop();
                if(!s.empty()){
                    y = s.top();
                    s.pop();
                    r = convertBoolToNumber(x) || convertBoolToNumber(y);
                    if (r == 1)
                        s.push('T');
                    else
                        s.push('F');
                }else{
                    cout<<"Invalid Filter Provided\n";
                    exit(1);
                }
                
            }else {
                // Logical NOT operation, only play a number
                x = s.top();
                s.pop();
                if (convertBoolToNumber(x) == 1)
                    s.push('F');
                else
                    s.push('T');
            }
            q.pop();
        }
    }
}

// remove Leading and training spaces present in string {eg : (      dport in 400,1000      )  -> (dport in 400,1000)}
void C_packetFilter::removeLeadingAndTrailingSpaces(string &filter_info){
    while(!filter_info.empty() && isspace(*filter_info.begin()))
        filter_info.erase(filter_info.begin());
    
    while(!filter_info.empty() && isspace(*filter_info.rbegin()))
        filter_info.erase(filter_info.length()-1);
}

void C_packetFilter::filter_fragmentation(string &filter_info){
    char exp[50];
    string_to_charArray(filter_info, exp);
    char *token = strtok(exp, " ");
    vector<st_filter_tokens> temp;
    while(token != NULL){
        st_filter_tokens sft;
        strcpy(sft.filter_tokens, token);
        temp.push_back(sft);
        token = strtok(NULL, " ");
    }
    
    if(temp.size() != 3){
        cout<<"Incorrect filter format."<<endl;
        exit(1);
    }
    
    st_ftrDep.filterVector.push_back(temp);
    
    return;
}

// breaks down filterString into single filters and store them in vector for further use in every packet
// checks if single filter is empty , if true then ignore
void C_packetFilter::getSingleFilter(string &filter_info){
    removeLeadingAndTrailingSpaces(filter_info);
    
    if(filter_info.size()!=0){
        filter_fragmentation(filter_info);
        st_ftrDep.boolFilter = st_ftrDep.boolFilter + ' ' ;
        st_ftrDep.pos.push_back(st_ftrDep.boolFilter.size()-1);
    }
}

// divide multiple filters into single filters , pass each individual filterString for validity if next character is && , || , )
void C_packetFilter::findAllFilters(string filter){
    string str = "";
    for (int i = 0; i < filter.size(); i++){
        if(filter[i] == '('){
            st_ftrDep.boolFilter = st_ftrDep.boolFilter + filter[i];
        }
        else if(filter[i] == '|'){
            if(filter[i+1] == '|'){
                if(str.size() > 0){
                    getSingleFilter(str);
                    str="";
                }
                st_ftrDep.boolFilter = st_ftrDep.boolFilter + filter[i];
                i++;
            }else{
                cout << "Invalid Operator \n";
                break;
            }
        }else if(filter[i] == '&'){
            if(filter[i+1] == '&'){
                if(str.size() > 0){
                    getSingleFilter(str);
                    str="";
                }
                st_ftrDep.boolFilter = st_ftrDep.boolFilter + filter[i];
                i++;
            }else{
                cout << "Invalid Operator \n";
                break;
            }
        }else if(filter[i] == ')'){
            if(str.size() > 0){
                getSingleFilter(str);
                
                str="";
            }
            
            st_ftrDep.boolFilter = st_ftrDep.boolFilter+filter[i];
        }else{
            str = str + filter[i];
        }
    }
}














