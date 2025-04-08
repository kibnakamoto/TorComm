#ifndef INTERFACE_H
#define INTERFACE_H

#ifndef Q_MOC_RUN

#include <QWidget>
#include <QApplication>
#include <QFile>
#include <QFont>

// base class of GUIs (inhereted by desktop/phone)
class GUI
{
    protected:
            inline static bool is_dark_theme;
            inline static QFont font;

    public:
            GUI()
            {
                font = QFont();
            }

            // Main interface of the chat app
            virtual void set_theme() = 0;

            // Ask a question (e.g. are you sure you want to close app?)
            // use switch case to handle question (save, discard, cancel)
            virtual int question(const char *question, const char *msg) = 0;

	        // give the user a warning
	        virtual void warning(const char *msg) = 0;

	        // give the user an error
	        virtual void error(const char *msg) = 0;

            // give the user a message/information
	        virtual void info(const char *msg) = 0;
};

#endif /* Q_MOC_RUN */

#endif /* INTERFACE_H */
