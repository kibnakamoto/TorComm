#ifndef GUI_H
#define GUI_H

#include <qt5/QtWidgets/QWidget>
#include <qt5/QtCore/QString>

#include "interface.h"

class GUI : public UI
{
	
		virtual void raise_warning(std::string msg) override;

		virtual void raise_error(std::string msg) override;

		virtual void print(std::string msg) override;
};

// make a file finder class
class FileFinder : public QWidget
{
	public:
			FileFinder() = default;
			
			find_one_file()
			{
				QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"),
                                                "/home",
                                                tr("Images (*.png *.xpm *.jpg)"));
			}
			
};
#endif /* GUI_H */
