#include <fstream>
#include <iostream>

using namespace std;

//argv[1] = testcase .in file
//argv[2] = testcase .out file
//argv[3] = user output file
//return 0 if correct and 1 if not correct

int main(int argc, const char *argv[])
{
    ifstream ac(argv[2]);
    ifstream me(argv[3]);
    
    int a, b;
    ac >> a;
    me >> b;
    
    if (a == b)
        return 0;
    else
        return 1;
}