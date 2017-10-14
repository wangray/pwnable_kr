#include <unistd.h>
#include <fcntl.h> // for open

int main(int argc, char *argv[])
{
    // write(1, "Hello World\n", 12); /* write "Hello World" to stdout */
     char data[128];

    int h = open("./flag.txt", 42, 0);
    read(h, data, 8);
    write(1, data, 8);

    _exit(0);                      /* exit with error code 0 (no error) */
}