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
#include <QApplication>

#include <iostream>
#include <string>

#include "interface.h"

// TODO: Add an interface for a texting tool
// TODO: Add Documentation while developing
// TODO: Add color schemes and make sure that all graphics abide the given color schemes
// TODO: Make a cipher suite selector

class Desktop : public GUI, public QWidget
{
    // add a specific theme
    void style_sheet(const QString &filename)
    {
        QFile file(filename);
        if (file.open(QFile::ReadOnly)) {
            QString styleSheet = QLatin1String(file.readAll());
            app->setStyleSheet(styleSheet);
        }
    }
    QApplication *app;

    public:
            // default constructor
            Desktop() = default;

            Desktop(QApplication &qapp) : app(&qapp)
            {
                 // default should be dark theme
                 is_dark_theme = true;

                 // set default theme
                 set_theme();
            }

            // Main interface of the chat app
            void set_theme() override
            {
                if(is_dark_theme) {
                    style_sheet("dark.qss");
                    
                } else { // light theme
                    // TODO: implement light.qss, light theme not supported yet
                    style_sheet("light.qss");
                    
                }
            }


            // Ask a question (e.g. are you sure you want to close app?)
            // use switch case to handle question (save, discard, cancel)
            int question(const char *question, const char *msg) override
            {
                QMessageBox qbox;
                qbox.setText(msg);
                qbox.setInformativeText(question);
                qbox.setStandardButtons(QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
                qbox.setDefaultButton(QMessageBox::Save);
                int response = qbox.exec();
                return response;
            }

	        // give the user a warning
	        void warning(const char *msg) override
            {
                    QMessageBox warning;
                    warning.setText(msg);
                    warning.setIcon(QMessageBox::Warning);
                    warning.setWindowTitle("Warning");
                    warning.exec();
            }

	        // give the user an error
	        void error(const char *msg) override
            {
                QMessageBox error;
                error.setIcon(QMessageBox::Critical);
                error.setWindowTitle("Error");
                error.setText(msg);
                error.exec();
            }

            // give the user a message/information
	        void info(const char *msg) override
            {
                QMessageBox box;
                box.setText(msg);
                box.setIcon(QMessageBox::Information);
                box.setWindowTitle("Information");
                box.exec();
            }
};

// make a file finder class
class Files : public Desktop
{
	public:
			Files()
            {
                // set default style, must initialize GUI class first in main since is_dark_theme is static
                style();
            }
			
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
