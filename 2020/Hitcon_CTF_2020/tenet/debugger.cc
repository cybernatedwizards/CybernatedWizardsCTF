#include <cstdio>
#include <cstdlib>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>

int PROCPID = 0;
int DAT_LOOPCOUNTER = 0; // DAT_00302044
long DAT_RIPS[0xfff] = {0}; // DAT_00302060
long long DAT_PEEKDATA = 0; //  DAT_0030a060

int perror(int pid, const char *arg)
{
  printf("Failed: %s\n", arg);
  kill(pid, 0);
  //wait(0);
  exit(1);
}

long getregs(int pid)
{
  struct user_regs_struct regs;
  int status = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  if(status != 0)
  {
    perror(pid, "ptrace");
  }
  return regs.rip;
}

void nop()
{
  return;
}

void setregs(int pid)
{
  int status = 0;
  long *regptrs = NULL;
  struct user_regs_struct regs = { 0 };
  struct user_fpregs_struct fpregs = { 0 };

  // set certain values
  regs.rip = 0xdead0080;
  regs.cs = 0x33;
  regs.ss = 0x2b;

  // set registers
  errno = 0;
  status = ptrace(PTRACE_SETREGS, PROCPID, 0, &regs);
  if(status != 0)
  {
    printf("ERROR SETREGS: 0x%X - PID: %d - errno: 0x%x\n", status, PROCPID, errno);
    perror(pid, "ptrace");
  }

  // set floating pointer registers
  errno = 0;
  status = ptrace(PTRACE_SETFPREGS, PROCPID, 0, &fpregs);
  if(status != 0)
  {
    printf("ERROR SETREGS: 0x%X - PID: %d - errno: 0x%x\n", status, PROCPID, errno);
    perror(pid, "ptrace");
  }
}

void zero_data(int pid)
{
  long long data;
  long long addr = 0x2170000;
  while(addr < 0x2171000)
  {
    data = ptrace(PTRACE_POKEDATA, pid, addr, 0);
    if(data != 0)
    {
      perror(pid, "ptrace");
    }
    addr += 0x8;
  }
}

long check_memory_zero(int pid)
{
  unsigned long data;
  unsigned long temp = 0;
  unsigned long addr = 0x2170000;

  // OR the entire contents of 0x1000 block
  while(addr < 0x2171000)
  {
    data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    temp = temp | data;
    addr += 0x8;
  }

  return data & 0xffffffffffffff00 | (temp == 0);
}

void randomize(int pid)
{
  int fd = open("/dev/urandom", 0);
  if(fd < 0)
  {
    perror(pid, "urandom");
  }

  ssize_t res = read(fd, &DAT_PEEKDATA, 8);
  if(res != 8)
  {
    perror(pid, "read urandom");
  }

  // copy DAT_PEEKDATA to the specified address
  long data = ptrace(PTRACE_POKEDATA, pid, 0x2170000, DAT_PEEKDATA);
  if(data != 0)
  {
    perror(pid, "ptrace");
  }
  return;
}

long get_rax_rcx(long *temp)
{
  struct user_regs_struct regs;
  long status;
  status  = ptrace(PTRACE_GETREGS, PROCPID, NULL, &regs);
  if(status != 0)
  {
    perror(PROCPID, "ptrace");
  }

  status = ptrace(PTRACE_PEEKDATA, PROCPID, regs.rip, 0);
  if(((status & 0xffff) == 0x050f) || ((status & 0xffff) == 0x340f))
  {
     *temp = regs.rax;
     return 1;
  }

  return 0;
}

long check_ss()
{
  struct user_regs_struct regs;
  long status;
  status  = ptrace(PTRACE_GETREGS, PROCPID, NULL, &regs);
  if(status != 0)
  {
    perror(PROCPID, "ptrace");
  }
  if((regs.cs == 0x33) && (regs.ss== 0x2b))
  {
    return 0;
  }

  return 1;
}

void update_rip(long temp)
{
  struct user_regs_struct regs;
  long status;
  status  = ptrace(PTRACE_GETREGS, PROCPID, NULL, &regs);
  if(status != 0)
  {
    perror(PROCPID, "ptrace");
  }

  regs.rip += temp;

  // set registers
  status = ptrace(PTRACE_SETREGS, PROCPID, 0, &regs);
  if(status != 0)
  {
    perror(PROCPID, "ptrace");
  }

  return;
}

char crazy_stuff()
{
  long temp;
  long y;

  do {
    // Released only when we do a sysenter
    char c1 = get_rax_rcx(&temp);
    if(c1 == '\0')
    {
      char c2 = check_ss(); // Must always be 0
      if(c2 != '\0')
      {
        perror(PROCPID, "invalid data");
      }
      return 0;
    }

    if(temp == 0x3c)
    {
      return 1;
    }

    update_rip(2);
  } while(true);

  return '\0';
}

char peek_data()
{
  long data = ptrace(PTRACE_PEEKDATA, PROCPID, 0x2170000,0);
  return DAT_PEEKDATA & 0xffffffffffffff00 | (data == DAT_PEEKDATA);
}

void exec_in_reverse()
{
  struct user_regs_struct regs;
  int temp;
  unsigned int temp2;
  pid_t pid;

  setregs(PROCPID);
  int loopcounter = DAT_LOOPCOUNTER;
  while(true)
  {
    loopcounter--;
    if(loopcounter < 0)
    {
      return;
    }

    int data = ptrace(PTRACE_GETREGS, PROCPID, NULL, &regs);
    if(data != 0)
    {
      perror(pid, "ptrace");
    }

    regs.rip = DAT_RIPS[loopcounter];
    long status = ptrace(PTRACE_SETREGS, PROCPID, NULL, &regs);
    if(status != 0)
    {
      perror(pid, "ptrace");
    }

    printf("RIP BACKWARD: 0x%X\n", regs.rip);
    long retval = ptrace(PTRACE_SINGLESTEP, PROCPID, 0, 0);
    if(retval != 0)
    {
      perror(pid, "ptrace");
    }

    temp = 0;
    pid = wait(&temp);
    if((temp & 0x7f) == 0)
    {
      break;
    }

    temp2 = (int)temp >> 8 & 0xff;
    if(temp2 != 5)
    {
      perror(PROCPID, "child dead");
    }
  }

  puts("exit too early...");
  _exit(1);
}

int Debugger(char *program)
{
  puts("Debugger");

  // Start the process and debug it
  PROCPID = fork();

  // CHILD
  if (PROCPID == 0)
  {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execve(program, 0, 0);
    perror(PROCPID, "execve");
  }

  // PARENT
  printf("Child PID: %i\n", PROCPID);
  long s = ptrace(PTRACE_ATTACH, PROCPID, 0, 0);
  if(s != 0)
  {
    perror(PROCPID, "ptrace");
  }

  int status = 0;
  int pid = waitpid(PROCPID, &status, 2);
  printf("Obtained PID: %d - status: 0x%X\n", pid, status);
  if((pid != PROCPID) || (status & 0xff) != 0x7f)
  {
    perror(pid, "the first wait");
  }

  bool finished = false;
  bool process_success = false;
  long retval = 0;
  int iteration = 0;

  while(true)
  {
    do {
      retval = ptrace(PTRACE_SINGLESTEP, PROCPID, 0, 0);
      if(retval != 0)
      {
        perror(pid, "single step");
      }
      wait(&status);

      // check child status
      if((status & 0x7f) == 0) { goto endprocessing; }
      if((status >> 8 & 0xffU) != 5)
      {
        perror(pid, "child dead unexpectedly.");
      }

      // check loop counter
      if(0xfff < DAT_LOOPCOUNTER)
      {
        perror(pid, "too many steps.");
      }

      // wait until reaching our shellcode and only then start processing
      if(!finished)
      {
        long rip = getregs(pid);
        if(rip == 0xdead0080)
        {
          printf("INSIDE\n");
          finished = true;
          nop();

          // go to the beginning of our shellcode (we're already here)
          setregs(pid);

          // read 0x1000 of memory which must succeed
          zero_data(pid);

          // set first 8-bytes of data with RANDOM
          randomize(pid);
        }
      }
      iteration++;
    } while (!finished);

    char x = crazy_stuff();
    if(x != '\0')
    {
      break;
    }


    // Store current RIP addresses into array
    long rip2 = getregs(pid);
    printf("RIP FORWARD: 0x%X\n", rip2);
    DAT_RIPS[DAT_LOOPCOUNTER]  = rip2;
    DAT_LOOPCOUNTER++;
  }
  process_success = true;

endprocessing:
  if(!process_success)
  {
    perror(pid, "error");
  }

  // TO GET HERE: mov eax, 0x3c; syscall
  printf("FINISH LOOP\n");

  char data2 = check_memory_zero(pid);
  if(data2 != '\x01')
  {
    perror(pid, "please swallow the cookie");
  }
  printf("FINISH SWALLOWING COOKIE\n");

  exec_in_reverse();
  printf("FINISH EXECUTING INSTRUCTIONS IN REVERSE\n");

  char data3 = peek_data();
  if(data3 != '\x01')
  {
    perror(pid, "you should vomit the cookie out");
  }

  printf("hitcon{FLAG}");

  return 0;
}

int main(int argc, char **argv)
{
  if(argc != 2)
  {
    printf("Usage: %s <program>\n", argv[0]);
    exit(1);
  }
  return Debugger(argv[1]);
}

