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
  * Date: 2025, Apr 5
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
#include <QVBoxLayout>
#include <QTextBrowser>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QScrollBar>
#include <QScrollArea>
#include <QDockWidget>
#include <QListWidget>
#include <QSplitter>

#include <iostream>
#include <string>

#include "interface.h"
#include "qnamespace.h"

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
    inline static QPushButton *send_button;
    inline static QTextEdit *textbox; // user input (enter to chat history)
    inline static const char *styler_filename;
    inline static QVBoxLayout *chat_history;

    public:
            // default constructor
            Desktop() = default;

            Desktop(QApplication &app) : app(&app)
            {
                 // default should be dark theme
                 is_dark_theme = true;

                 // set default font size
                 GUI::font.setPointSize(15);  // TODO: make font/fontsize controlled in the settings

                 // set default theme
                 set_theme();

                 // start a interface to start texting.
                 start_interface();
            }

            // start the main interface for texting
            void start_interface()
            {
                QHBoxLayout *main_layout = new QHBoxLayout(this); // uses side-menu (contacts) + layout
                QWidget *layout_widget = new QWidget(this);
                QVBoxLayout *layout = new QVBoxLayout(layout_widget);

                // layout for chat history
                QScrollArea *scroller = new QScrollArea(this);
                QWidget *container = new QWidget(scroller);
                chat_history = new QVBoxLayout(container);
                container->setLayout(chat_history);
                scroller->setWidget(container);
                scroller->setWidgetResizable(true);
                layout->addWidget(scroller);
                scroller->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding); // might not be necesarry

                // define the textbox to write new messages + the send button (horizontal layout)
                QHBoxLayout *hlayout = new QHBoxLayout(this);
                textbox = new QTextEdit(this);
                textbox->setFixedHeight(50); // TODO: make this number depend on dimensions of screen
                textbox->setStyleSheet(styler_filename);
                textbox->setPlaceholderText("Enter Text Message Here...");

                // set font size of textbox
                textbox->setFont(GUI::font);

                send_button = new QPushButton(this);
                send_button->setText("Send");
                send_button->setFont(GUI::font);
                send_button->setFixedHeight(50); // TODO: make this number depend on dimensions of screen
                send_button->setStyleSheet(styler_filename);
                hlayout->addWidget(textbox);
                hlayout->addWidget(send_button);

                // add the text box + send button to the layout with chat history
                layout->addLayout(hlayout);

                // add contacts side bar menu
                // QDockWidget *sidemenu = new QDockWidget("Contacts", this);
                // sidemenu->setFeatures(QDockWidget::DockWidgetMovable);
                // sidemenu->setFloating(false); // shouldn't float
                // sidemenu->setMaximumWidth(300);
                // sidemenu->setMinimumWidth(100);
                // sidemenu->setWidget(contacts);

                QWidget *sidemenu = new QWidget(this);
                QVBoxLayout *sidemenu_layout = new QVBoxLayout(sidemenu);
                sidemenu->setMaximumWidth(300);
                sidemenu->setMinimumWidth(100);
        
                // add contacts
                QListWidget *contacts = new QListWidget(sidemenu);
                contacts->setMaximumWidth(300);
                contacts->setMinimumWidth(100);
                contacts->addItem("contact 1"); // should be all unique

                sidemenu_layout->addWidget(contacts);
                sidemenu->setLayout(sidemenu_layout);
        

                QSplitter* splitter = new QSplitter(Qt::Horizontal, this);
                splitter->addWidget(sidemenu);
                splitter->addWidget(layout_widget);

                main_layout->addWidget(splitter);
                // main_layout->addWidget(sidemenu);
                // main_layout->addWidget(layout_widget);

                // connect the button and the message sender
                connect(send_button, &QPushButton::clicked, this, &send_text_message);
            }

            // only to send text messages
            static void send_text_message()
            {
                QString text = textbox->toPlainText().trimmed(); // get text
                if (!text.isEmpty()) {
                    QLabel *label = new QLabel(text);
                    label->setWordWrap(true);
                    label->setStyleSheet("background-color: #224466; border-radius: 10px; padding: 10px; margin: 5px; max-width: 300px;");
                    label->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                    label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed); // stop size from resizing
                    // label->setFixedHeight(label->sizeHint().height());  // Ensures the label has a fixed height
                    // label->setFixedWidth(label->sizeHint().width());  // Ensures the label has a fixed height
                    chat_history->addStretch(1); // places the text to the top of chat_history

                    // stop resizing per message added, scroll if needed
                    QWidget *parentWidget = chat_history->parentWidget();
                    if (parentWidget) {
                        parentWidget->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
                    }
                    QHBoxLayout *wrapper = new QHBoxLayout;
                    wrapper->addWidget(label);
                    wrapper->addStretch();
                    QWidget *wrapper_w = new QWidget;
                    wrapper_w->setLayout(wrapper);

                    // Insert above stretch (or just add if you're not using a bottom stretch)
                    chat_history->addWidget(wrapper_w);

                    // Scroll to the bottom of the texts (as new texts are added)
                    QScrollBar *scrollBar = chat_history->parentWidget()->findChild<QScrollBar*>();
                    if (scrollBar) {
                        scrollBar->setValue(scrollBar->maximum());
                    }

                    // clear text box
                    textbox->clear();
                }
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
			Files() = default;
			
            // select files, they will be parsed and sent. If sending multiple files, they will be
            // parsed/sent one by one
            QStringList select_files()
			{
                // theme of file selector is controlled by the system
                 QStringList filenames = QFileDialog::getOpenFileNames(this, "Select files", QString(),
                                                                       "All Files (*.*)");
                return filenames;
			}
};

#endif /* GUI_H */
