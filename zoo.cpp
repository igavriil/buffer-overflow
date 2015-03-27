#include <iostream>
#include <cstdlib>
#include <cstring>
#include <getopt.h>

#define MAX_BUFFER_SIZE 256

class Animal{
private:
  char name[MAX_BUFFER_SIZE];
public:
  Animal() { strcpy(name, "Ylvis"); }
  void set_name(char *nname) { strcpy(name, nname); }
  char *get_name() { return name; }
  virtual void speak() = 0;
};

class Cow : public Animal{
public:
  void speak();
};

class Fox  : public Animal{
public:
  void speak();
};

/* dog woof
cat meow
bird tweet
mouse squeek
cow moo
frog croak
elephant toot
duck quack
fish blub
seal owowow
fox  
Gering-ding-ding-ding-dingeringeding
Wa-pa-pa-pa-pa-pa-pow
Hatee-hatee-hatee-ho
Joff-tchoff-tchoff-tchoffo-tchoffo-tchoff
Jacha-chacha-chacha-chow
Fraka-kaka-kaka-kaka-kow
A-hee-ahee ha-hee
A-oo-oo-oo-ooo
*/

void Cow::speak()
{
  std::cout << get_name() << " says Moo.\n";
  return;
}

void Fox::speak()
{
  std::cout << get_name() << " says Hatee-hatee-hatee-ho.\n";
  return;
}

void usage()
{
  std::cout << "Usage: zoo [options]\n"
	    << "Options:\n"
	    << "\t-c <name> : Set cow name\n"
	    << "\t-f <name> : Set fox name\n"
	    << "\t-s : Instruct animals to speak\n"
	    << "\t-h : Print options\n";
  return;
}

int main(int argc, char *argv[])
{
  Animal *a1, *a2;
  bool speak = false;
  char c;
  
  if (argc < 2){
    usage();
    return 1;
  }

  a1 = new Cow;
  a2 = new Fox;

  while ((c = getopt(argc, argv, "hsc:f:")) != -1){
    switch (c){
    case 'h':
      usage();
      return 0;
    case 's':
      speak = true;
      break;
    case 'c':
      a1 -> set_name(optarg);
      break;
    case 'f':
      a2 -> set_name(optarg);
      break;
    case '?':
      usage();	
      return 1;
    }
  }

  if (speak){
    a1 -> speak();
    a2 -> speak();
  }else
    std::cout <<"Another silent night in the zoo\n";
    
  delete a2;
  delete a1;
  return 0;
}
