 /* Copyright (c) 2023 Taha
  * this program is free software: you can redistribute it and/or modify
  * it under the terms of the gnu general public license as published by
  * the free software foundation, either version 3 of the license, or
  * (at your option) any later version.
  * this program is distributed in the hope that it will be useful,
  * but without any warranty; without even the implied warranty of
  * merchantability or fitness for a particular purpose.  see the
  * gnu general public license for more details.
  * you should have received a copy of the gnu general public license
  * along with this program.  if not, see <https://www.gnu.org/licenses/>.
  *
  * Author: Taha
  * Date: 2023, Dec 9
  * Description: This is the main user interace. This is for people to securely communicate over a public channel using a P2P system (TCP/IPv6). 
  */

#ifndef GUI_CPP
#define GUI_CPP

#include <iostream>

#include <QApplication>

#include "gui.h"


int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    Desktop gui(app);
    Files files;
    gui.setWindowTitle("TorComm");
    gui.resize(1600/2, 900/2);
    gui.show();
    app.exec();
	return 0;
}

#endif /* GUI_CPP */
