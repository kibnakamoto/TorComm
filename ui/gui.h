#ifndef GUI_H
#define GUI_H

#include <QWidget>
#include <QString>
#include <QFileDialog>
#include <QMessageBox>
#include <QErrorMessage>

#include <iostream>
#include <string>

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
