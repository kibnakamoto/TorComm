#include <iostream>

#include <QApplication>

#include "gui.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    Files files;
    GUI gui;
    //gui.info("here is a message");
    //gui.warning("here is a warning");
    gui.error("here is an error");
	return 0;
}
