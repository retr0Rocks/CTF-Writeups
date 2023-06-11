#include <stdio.h>
#include <stdlib.h>

typedef struct {
  char robot_name[0x10];
  char robot_creator[0x10];
  char robot_reference[0x8];
  char robot_description[0x30];
} robot;

typedef struct {
  robot *robots[0x20];
} robot_factory;
robot_factory *factories[0x20];


int factory_count = 0;

void create_factory() {
  int index = -1;
  do {
    printf("factory index: ");
    scanf("%d", &index);
  } while(index < 0 || index > 0x20 || factories[index] != NULL);
  factories[index] = malloc(sizeof(robot_factory));
  factory_count++; 
}
void delete_factory() {
  int index = -1;
  do {
    printf("factory index: ");
    scanf("%d", &index);
  } while (index < 0 || factories[index] == NULL);
  free(factories[index]);
  factories[index] = NULL;
  factory_count--;
}
void spawn_robot() {
  int index = -1, robot_index = -1;
  do {
    printf("factory index: ");
    scanf("%d", &index);
  } while (index < 0 ||factories[index] == NULL);
  do {
    printf("robot index: ");
    scanf("%d", &robot_index);
  } while (robot_index < 0 ||factories[index]->robots[robot_index] != NULL);

  factories[index]->robots[robot_index] = malloc(sizeof(robot));
  printf("robot name: \n");
  read(0, factories[index]->robots[robot_index]->robot_name, 0x10);
  printf("robot creator: \n");
  read(0, factories[index]->robots[index]->robot_creator, 0x10);
  printf("robot reference: \n");
  read(0, factories[index]->robots[robot_index]->robot_reference, 0x8);
  printf("robot description: \n");
  read(0, factories[index]->robots[robot_index]->robot_description, 0x30);

}

void fix_robot() {
  int index = -1, robot_index = -1;
  do {
    printf("factory index: ");
    scanf("%d", &index);
  } while (index < 0 ||factories[index] == NULL);
  do {
    printf("robot index: ");
    scanf("%d", &robot_index);
  } while (robot_index < 0 ||factories[index]->robots[robot_index] == NULL);

  printf("introduce the new robot name: \n");
  read(0, factories[index]->robots[robot_index]->robot_name, 0x10);

}
void view_robot() {
  int index = -1, robot_index = -1;
  do {
    printf("factory index: ");
    scanf("%d", &index);
  } while (index < 0 ||factories[index] == NULL);
  do {
    printf("robot index: ");
    scanf("%d", &robot_index);
  } while (robot_index < 0 ||factories[index]->robots[robot_index] == NULL);
  
  printf("robot name : %s\n", factories[index]->robots[robot_index]->robot_name);
  printf("robot creator: %s\n", factories[index]->robots[robot_index]->robot_creator);
  printf("robot reference: %s\n", factories[index]->robots[robot_index]->robot_reference);
  printf("robot_description: %s\n", factories[index]->robots[robot_index]->robot_description);

}
void delete_robot() {
  int index = -1, robot_index = -1;
  do {
    printf("factory index: ");
    scanf("%d", &index);
  } while (index < 0 ||factories[index] == NULL);
  do {
    printf("robot index: ");
    scanf("%d", &robot_index);
  } while (robot_index < 0 ||factories[index]->robots[robot_index] == NULL);

  free(factories[index]->robots[robot_index]);
  factories[index]->robots[robot_index] = NULL;
}
int menu(){
  int choice = -1;
  printf("1. create factory\n2. spawn robot\n3. fix robot\n4. inspect robot\n5. delete robot\n6. delete factory\n7. quit\n>>> ");
  scanf("%d", &choice);
  return choice;
}
int main() {
  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);
  setvbuf(stderr, 0, _IONBF, 0);
  for (;;) {
    switch(menu()) {
      case 1:
        create_factory();
        break;
      case 2:
        spawn_robot();
        break;
      case 3:
        fix_robot();
        break;
      case 4:
        view_robot();
        break;
      case 5:
        delete_robot();
        break;
      case 6:
        delete_factory();
        break;
      case 7: exit(0);
      default : printf("INVALID CHOICE\n"); break;
    }
  }

}
