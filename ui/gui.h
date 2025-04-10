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
#include <QScroller>
#include <QEasingCurve>
#include <QObject>
#include <QStackedWidget>
#include <QTimer>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QLineEdit>

#include <iostream>
#include <string>

#include "interface.h"
#include "qnamespace.h"

// TODO: Add Documentation while developing
// TODO: Add color schemes and make sure that all graphics abide the given color schemes
// TODO: Make a cipher suite selector


class Desktop : public QWidget, public GUI
{
    Q_OBJECT // macro to enable slots

    // add a specific theme
    void style_sheet(const QString &filename)
    {
        QFile file(filename);
        if (file.open(QFile::ReadOnly)) {
            QString styleSheet = QLatin1String(file.readAll());
            app->setStyleSheet(styleSheet);
        }
    }

    // this is used for chat_histories values. draft is written to textbox as a default value every time contacts is changed.
    struct ScrollerAndDraft
    {
        std::string draft;
        QScrollArea *scroller;

        ScrollerAndDraft(std::string draft, QScrollArea *scroller)
        {
            this->scroller = scroller;
            this->draft = draft;
        } 
    };

    QApplication *app;
    QTextEdit *textbox; // user input (enter to chat history)
    inline static const char *styler_filename; // e.g. dark.qss
    inline static std::map<std::string, ScrollerAndDraft*> chat_histories; // chat history per contact
    inline static QListWidget *contacts;
    QVBoxLayout *chat_history; // currently selected chat_history
    std::string current_contact;
    QStackedWidget *chat_history_stack;
    QLineEdit *search_contacts; // search bar for contacts
    QPushButton *search_button; // search bar toggle button

    public:
            // default constructor
            Desktop() = default;

            Desktop(QApplication &app) : app(&app)
            {
                // default should be dark theme
                is_dark_theme = true; // TODO: add to settings.json

                // set default font size
                GUI::font.setPointSize(15);  // TODO: make font/fontsize controlled in the settings

                // set default theme
                set_theme();

                // start a interface to start texting.
                // This class starts an interface, but user should be able to start multiple interfaces
                start_interface();
            }

            // start the main interface for texting
            void start_interface()
            {
                QHBoxLayout *main_layout = new QHBoxLayout(this); // uses side-menu (contacts) + layout
                QWidget *layout_widget = new QWidget(this);
                QVBoxLayout *layout = new QVBoxLayout(layout_widget); // holds the chat history
                chat_history_stack = new QStackedWidget(this);
                layout->addWidget(chat_history_stack);

                // set icons
                QIcon send_button_icon;
                QIcon search_button_icon;
                if(is_dark_theme) {
                    get_inverse_icon_symbol(send_button_icon, "../symbols/send_symbol.png");
                    get_inverse_icon_symbol(search_button_icon, "../symbols/search_symbol.png");
                } else {
                    get_icon_symbol(send_button_icon, "../symbols/send_symbol.png");
                    get_icon_symbol(send_button_icon, "../symbols/search_symbol.png");
                    
                }


                // add contacts side bar menu
                QWidget *sidemenu = new QWidget(this);
                QVBoxLayout *sidemenu_layout = new QVBoxLayout(sidemenu);
                sidemenu->setMaximumWidth(300);
                sidemenu->setMinimumWidth(100);

                // add contacts label to sidemenu
                QLabel *label_contacts = new QLabel();
                QHBoxLayout *contacts_bar = new QHBoxLayout();
                label_contacts->setText("Contacts");
                label_contacts->setFont(GUI::font_title);
                contacts_bar->addWidget(label_contacts);

                // add search bar for contacts
                search_button = new QPushButton(this);
                search_contacts = new QLineEdit(this);
                search_contacts->setPlaceholderText("Find Contact...");
                search_contacts->setVisible(false);
                contacts_bar->addWidget(search_button);
                contacts_bar->addWidget(search_contacts);
                connect(search_contacts, &QLineEdit::textChanged, this, &Desktop::contacts_filter);
                connect(search_button, &QPushButton::clicked, this, &Desktop::showSearchBar);
                QTimer::singleShot(0, this, [this]() { // fixes segmentation fault regarding search contacts object creation
                    search_contacts->installEventFilter(this);
                });
                search_button->setIcon(search_button_icon);
                search_button->setIconSize(QSize(25,25));
                
                // add contacts label + search bar to sidemenu (above contacts list)
                sidemenu_layout->addLayout(contacts_bar);

                // initialize textbox here since it's needed for added contacts (saving draft messages in chat_histories)
                textbox = new QTextEdit(this);
                textbox->setFixedHeight(44); // same as send_button
                textbox->setStyleSheet(styler_filename);
                textbox->setPlaceholderText("Enter Text Message Here...");
                textbox->setFont(GUI::font);

                // same as chat history but different width
                textbox->setStyleSheet(R"(
                    QScrollBar:vertical {
                        background: transparent;
                        width: 7px;        
                        margin: 0px;        
                        border-radius: 3px; 
                    }
                    
                    QScrollBar::handle:vertical {
                        background: #888;  
                        min-height: 30px;  
                        border-radius: 3px;
                        max-height: 70px;  
                    }
                    
                    QScrollBar::handle:vertical:hover {
                        background: #555;
                    }
                    
                    /* Arrows */
                    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                        background: transparent;
                        border: none;
                    }
                    
                    QScrollBar:vertical:disabled {
                        background: transparent; 
                    }
                    
                    QScrollBar::groove:vertical {
                        background: transparent;
                    }


                )");


                // add contacts to side bar
                contacts = new QListWidget(sidemenu);
                contacts->setMaximumWidth(300);
                contacts->setMinimumWidth(100);
                contacts->setFont(QFont(GUI::font_title.family(), GUI::font_title.pointSize()));
                connect(contacts, &QListWidget::itemClicked, this, &Desktop::open_chat_of_contact);

                // example contact, should be loaded from a file
                add_new_contact("contact 1");
                add_new_contact("contact 2");
                for(int i=3;i<20;i++) {
                    std::string tmp = "contact " + std::to_string(i);
                    add_new_contact(tmp);
                }

                // open default contact
                if (contacts->count() > 0) {
                    contacts->setCurrentRow(0);
                    open_chat_of_contact(contacts->currentItem());
                }

                contacts->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff); // default rule for scrollbar, more rules defined in timing function
                sidemenu_layout->addWidget(contacts);
                sidemenu->setLayout(sidemenu_layout);

                // set style for contacts scrolling
                contacts->setStyleSheet(R"(
                    QScrollBar:vertical {
                        background: transparent;
                        width: 5px;
                        margin: 0px;
                        border-radius: 5px;
                    }
                
                    QScrollBar::handle:vertical {
                        background: #666666;
                        min-height: 20px;
                    }
                
                    QScrollBar::handle:vertical:hover {
                        background: #777777;
                    }

                    QScrollBar::add-line:vertical,
                    QScrollBar::sub-line:vertical {
                        height: 0px;
                    }
                
                    QScrollBar::add-page:vertical,
                    QScrollBar::sub-page:vertical {
                        background: none;
                    })");

                // add empty space at the bottom
                QWidget *bottomSpacer = new QWidget();
                bottomSpacer->setFixedHeight(45);  // empty space for less clattered look
                sidemenu_layout->addWidget(bottomSpacer);

                // define the textbox to write new messages + the send button (horizontal layout)
                QHBoxLayout *hlayout = new QHBoxLayout();
                QPushButton *send_button = new QPushButton(this);
                send_button->setFixedHeight(45); // TODO: make this number depend on dimensions of screen (not app window size)
                send_button->setStyleSheet(styler_filename);

                // add send button icon 
                send_button->setIcon(send_button_icon);
                send_button->setIconSize(QSize(30, 26));

                hlayout->addWidget(textbox);
                hlayout->addWidget(send_button);

                // add the text box + send button to the layout with chat history
                layout->addLayout(hlayout);

                // make size of contacts sidebar adjustable by mouse
                QSplitter* splitter = new QSplitter(Qt::Horizontal, this);
                splitter->addWidget(sidemenu);
                splitter->addWidget(layout_widget);
                splitter->setSizes({150, layout_widget->width()});
                main_layout->addWidget(splitter);

                // connect the button and the message sender
                connect(send_button, &QPushButton::clicked, this, &Desktop::send_text_message);
                splitter->setSizes({150, width()-150});

                // set scrollbar timers
                set_1s_timer_scrollbar();
            }

            // get symbol based on theme
            static inline void get_icon_symbol(QIcon &icon, const char *icon_path)
            {
                icon = QIcon(icon_path);
            }

            // get symbol based on theme (inverse dark button to make it light colored for visibility in dark theme)
            static inline void get_inverse_icon_symbol(QIcon &icon, const char *icon_path)
            {
                // inverse the colors
                QPixmap pixmap(icon_path); // the symbol is for light theme
                QImage img = pixmap.toImage();
                img.invertPixels();
                icon = QIcon(QPixmap::fromImage(img));
            }

            template<typename T>
            struct ScrollerFade
            {
                T widget;
                QTimer *timer;
                QPropertyAnimation *fader;
                QGraphicsOpacityEffect *opacity;
                QScrollBar *scroller;
                ScrollerFade(T widget, QScrollBar *scroller, QWidget *parent) : widget(widget)
                {
                    this->scroller = scroller;
                    this->timer = new QTimer(parent);
                    timer->setSingleShot(true);
                    fader = static_cast<Desktop*>(parent)->fade(scroller, opacity);

                    // hide again after a second
                    connect(timer, &QTimer::timeout, [this]() {
                        fader->start();
                    });
                }

                // parameter of connect function to fade when typing and/or scrolling
                std::function<void()> show_scrollbar_temp_f = [this]() {
                    widget->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
                    opacity->setOpacity(1.0); // reset to visible if its currently fading
                    fader->stop(); // stop any ongoing animation
                    timer->start(1000);
                };
            };

            ScrollerFade<QTextEdit*> *scroller_fade1;   // for textbox
            std::map<QVBoxLayout*, ScrollerFade<QScrollArea*>*> scroller_fade2; // for chat history
            ScrollerFade<QListWidget*> *scroller_fade3; // for contacts

            // scrollbar should dissapear after a second of no use (this doesn't include chat history, that is already made in add_new_contact)
            void set_1s_timer_scrollbar()
            {
                // textbox scroller
                this->scroller_fade1 = new ScrollerFade<QTextEdit*>(this->textbox, textbox->verticalScrollBar(), this);

                // show when typing or scrolling with mouse
                connect(textbox, &QTextEdit::textChanged, this->scroller_fade1->show_scrollbar_temp_f);
                if(textbox->verticalScrollBar()) {
                    connect(textbox->verticalScrollBar(), &QScrollBar::valueChanged, this->scroller_fade1->show_scrollbar_temp_f);
                }

                // contacts scrollbar
                QScrollBar *scroller_contacts = contacts->verticalScrollBar();
                this->scroller_fade3 = new ScrollerFade<QListWidget*>(contacts, scroller_contacts, this);

                // show when scrolling with mouse
                connect(scroller_contacts, &QScrollBar::valueChanged, this->scroller_fade3->show_scrollbar_temp_f);

                // add rule for all scrollers to show when mouse hovers over them
                scroller_contacts->installEventFilter(this);
                textbox->verticalScrollBar()->installEventFilter(this);
            }

            // make a widget fade
            // opacity: arguement, shouldn't be set to anything.
            QPropertyAnimation *fade(QWidget *widget, QGraphicsOpacityEffect *&opacity)
            {
                // fade the widget
                opacity = new QGraphicsOpacityEffect(widget);
                widget->setGraphicsEffect(opacity);
                opacity->setOpacity(1.0); // initially visible
            
                // animation setup
                QPropertyAnimation *fader = new QPropertyAnimation(opacity, "opacity");
                fader->setDuration(500); // fades for 500ms
                fader->setStartValue(1.0);
                fader->setEndValue(0.0);
                return fader;
            }

            // event filter to make scroller visible when moved mouse over it
            bool eventFilter(QObject *watched, QEvent *event) override
            {
                // scrollers
                QScrollBar *textbox_scroller = textbox->verticalScrollBar();
                QScrollArea *chat_history_scrollarea = qobject_cast<QScrollArea*>(chat_history->parentWidget()->parentWidget()->parentWidget());
                QScrollBar *chat_history_scroller = chat_history_scrollarea->verticalScrollBar();
                QScrollBar *contacts_scroller = contacts->verticalScrollBar();

                // for textbox, chat history, and contacts
                if (watched == textbox_scroller && event->type() == QEvent::Enter) {
                    scroller_fade1->show_scrollbar_temp_f();
                    return true;
                } else if (watched == chat_history_scroller && event->type() == QEvent::Enter) {
                    scroller_fade2[chat_history]->show_scrollbar_temp_f();
                    return true;
                } else if (watched == contacts_scroller && event->type() == QEvent::Enter) {
                    scroller_fade3->show_scrollbar_temp_f();
                    return true;
                } else if (watched == search_contacts && event->type() == QEvent::FocusOut) {
                    // toggle_search_bar();
                    hideSearchBar();
                }

                return QWidget::eventFilter(watched, event);
            }

            // add new contact
            // TODO: this function needs to be tied to ../configure.json (managed in keys.cpp)
            // TODO: make a load_contacts function to load previous contacts. Saved chats are in sessions/contact_name (encrypt name and everything else)
            void add_new_contact(std::string contact_name)
            {
                QScrollArea *scroller = new QScrollArea(this);
                scroller->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff); // default rule for scrollbar, more rules defined in timing function
                scroller->setWidgetResizable(true);
                QWidget *chat_view = new QWidget(scroller);
                
                QVBoxLayout *new_chat_history = new QVBoxLayout(chat_view);
                contacts->addItem(contact_name.c_str());
                chat_view->setLayout(new_chat_history);
                scroller->setWidget(chat_view);
                chat_history_stack->addWidget(scroller);

                // save message draft in textbox by contact
                chat_histories[contact_name] = new ScrollerAndDraft("", scroller);

                // add scroller fade
                scroller_fade2[new_chat_history] = new ScrollerFade<QScrollArea*>(scroller, scroller->verticalScrollBar(), this);

                // show when scrolling with mouse
                connect(scroller->verticalScrollBar(), &QScrollBar::valueChanged, scroller_fade2[new_chat_history]->show_scrollbar_temp_f);
                scroller->verticalScrollBar()->installEventFilter(this);
            }

    private slots:
            void showSearchBar() {
                search_button->hide();
                search_contacts->show();
                search_contacts->setFocus();
            }

            void hideSearchBar() {
                search_contacts->hide();
                search_contacts->clear();
                search_button->show();
                contacts_filter("");
            }


            // search button, if clicked, toggle search bar
            void toggle_search_bar()
            {
                 search_contacts->setVisible(!search_contacts->isVisible());
                 if (search_contacts->isVisible()) {
                     search_button->setVisible(false);
                     search_contacts->setFocus();
                 } else {
                     search_button->setVisible(true);
                     search_contacts->clear();
                     contacts_filter("");
                 }
            }

            // handle search bar for contacts
            void contacts_filter(const QString &input)
            {
                for(int i=0;i<contacts->count();i++) {
                    QListWidgetItem *item = contacts->item(i);
                    bool found = item->text().toLower().contains(input.toLower()); // find input, ignore case
                    item->setHidden(!found); // hide if not found
                }
            }

            // when clicked on contact
            void open_chat_of_contact(QListWidgetItem *item)
            {
                std::string contact = item->text().toStdString(); // name of contact
                
                // get contact and place chat history
                ScrollerAndDraft *historyndraft = chat_histories[contact];

                // set the previous contacts message in textbox (draft)
                if(!current_contact.empty())
                    chat_histories[current_contact]->draft = textbox->toPlainText().toStdString();

                // set saved draft text for this contact
                textbox->setText(historyndraft->draft.c_str());
                
                // store this for later use when switching
                chat_history_stack->setCurrentWidget(historyndraft->scroller);
                chat_history = qobject_cast<QVBoxLayout*>(historyndraft->scroller->widget()->layout());
                current_contact = contact; // set current contact
            }

            // only to send text messages
            void send_text_message()
            {
                QString text = textbox->toPlainText().trimmed(); // get text

                // add zero width space every 30 characters
                auto add_zero_width_spaces = [](std::string str) {
                    std::string out;
                    uint8_t count = 0; // how many iterations without space
                    for(size_t i=0;i<str.length();i++) {
                        out+=str[i];
                        if (str[i] != ' ')
                            count++;
                        else {
                            count = 0; // reset counter if space found
                        }

                        if(count > 30) {
                            out += "\xE2\x80\x8B"; // zero-width space
                            count = 0; // reset counter after adding
                        }
                    }
                    return out;
                };
                text = add_zero_width_spaces(text.toStdString()).c_str();

                if (!text.isEmpty()) {
                    QLabel *label = new QLabel(text); // text
                    label->setWordWrap(true);
                    label->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                    label->setMaximumWidth(width()/2 - 25); // half of screen + 25px padding
                    chat_history->addStretch(1); // places the text to the top of selected chat_history
                
                    // Resize label so that it fits to text
                    // label->adjustSize();

                    
                    // 3) Style it like a chat bubble
                    label->setStyleSheet(R"(
                        background-color: #224466;
                        border-radius: 10px;
                        padding: 10px;
                        margin: 5px;
                    )");
                    
                    // 4) Let it resize vertically to fit the text
                    label->adjustSize();  // now its height == height needed to show all text

                    // stop resizing per message added, scroll if needed
                    QWidget *parent = chat_history->parentWidget();
                    if (parent) {
                        parent->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
                    }
                    QHBoxLayout *wrapper = new QHBoxLayout;
                    wrapper->addWidget(label);
                    wrapper->addStretch();
                    QWidget *wrapper_w = new QWidget;
                    wrapper_w->setLayout(wrapper);

                    // Insert above stretch (or just add if you're not using a bottom stretch)
                    chat_history->addWidget(wrapper_w);

                    // Scroll to the bottom of the texts (as new texts are added)
                    QScrollArea *scrollarea = qobject_cast<QScrollArea*>(parent->parentWidget()->parentWidget());
                    if(scrollarea) {
                        QScrollBar *scrollbar = scrollarea->verticalScrollBar();
                        if (scrollbar) {
                            // add a little delay so that it updates it right away
                            QTimer::singleShot(10, this, [scrollbar] {
                                scrollbar->setValue(scrollbar->maximum()); // Scroll to the bottom
                            });
                            scrollbar->setValue(scrollbar->maximum());
                        }
                    }

                    // clear text box
                    textbox->clear();
                }
            }

    public:
            // Main interface of the chat app
            void set_theme() override
            {
                if(is_dark_theme) {
                    style_sheet("../dark.qss"); // in build folder
                } else { // light theme
                    // TODO: implement light.qss, light theme not supported yet
                    style_sheet("../light.qss");
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
