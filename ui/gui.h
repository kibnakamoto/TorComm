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
  * Description: This is the main file of this project. This is for people to securely communicate over a public channel using a P2P system (TCP/IPv6). 
  */

#ifndef GUI_H
#define GUI_H

#include <QWidget>
#include <QString>
#include <QFileDialog>
#include <QMessageBox>
#include <QErrorMessage>

#include <iostream>
#include <string>

// TODO: Add an interface for a texting tool
// TODO: Add Documentation while developing
// TODO: Add color schemes and make sure that all graphics abide the given color schemes
// TODO: Make a cipher suite selector

class GUI : public QWidget
{
    public:
	        // give the user a warning
	        void warning(const char *msg)
            {
                    QMessageBox warning;
                    warning.setText(msg);
                    warning.setIcon(QMessageBox::Warning);
                    warning.setWindowTitle("Caution");
                    warning.exec();
            }

	        // give the user an error
	        void error(const char *msg)
            {
                QErrorMessage error;
                error.showMessage(msg);
                error.exec();
            }

            // give the user a message/information
	        void info(const char *msg)
            {
                QMessageBox box;
                box.setText(msg);
                box.exec();
            }
};

// make a file finder class
class Files : public QWidget
{
	public:
			Files() = default;
			
            // select files, they will be parsed and sent. If sending multiple files, they will be
            // parsed/sent one by one
            QStringList select_files()
			{
                 QStringList filenames = QFileDialog::getOpenFileNames(this, "Select files", QString(),
                                                                       "All Files (*.*)");
                return filenames;
			}
};
#endif /* GUI_H */
