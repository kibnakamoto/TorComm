#ifndef GUI_H
#define GUI_H

#include <qt5/QtWidgets/QWidget>
#include <qt5/QtCore/QString>

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
