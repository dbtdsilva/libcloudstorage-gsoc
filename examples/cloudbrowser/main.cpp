/*****************************************************************************
 * main.cpp : cloudbrowser main function
 *
 *****************************************************************************
 * Copyright (C) 2016 VideoLAN
 *
 * Authors: Paweł Wegner <pawel.wegner95@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef WITH_QMLPLAYER
#include <QGuiApplication>
#else
#include <QApplication>
#endif

#include <QResizeEvent>
#include <iostream>

#include "MediaPlayer.h"
#include "Window.h"

#ifndef WITH_QMLPLAYER

class MainWidget : public QWidget {
 public:
  MainWidget()
      : media_player_(MediaPlayer::instance(this)),
        window_(media_player_.get()),
        container_(createWindowContainer(&window_, this)) {
    container_->setFocus();

    media_player_->setStyleSheet("background-color:black;");
    media_player_->show();

    connect(&window_, &Window::showWidgetPlayer, this,
            [this]() { container_->hide(); });
    connect(&window_, &Window::hideWidgetPlayer, this,
            [this]() { container_->show(); });
  }

 protected:
  void resizeEvent(QResizeEvent* e) {
    QWidget::resizeEvent(e);
    media_player_->resize(e->size());
    container_->resize(e->size());
  }

  void keyPressEvent(QKeyEvent* e) {
    QWidget::keyPressEvent(e);
    if (e->isAccepted()) return;
    if (e->key() == Qt::Key_Q) {
      window_.stop();
      container_->setFocus();
    } else if (e->key() == Qt::Key_P)
      media_player_->pause();
  }

 private:
  std::unique_ptr<MediaPlayer> media_player_;
  Window window_;
  QWidget* container_;
};

#endif

int main(int argc, char* argv[]) {
  try {
#ifdef WITH_QMLPLAYER
    QGuiApplication app(argc, argv);
    Window window(nullptr);
#else
    QApplication app(argc, argv);
    MainWidget window;
#endif
    app.setOrganizationName("VideoLAN");
    app.setApplicationName("cloudbrowser");

    window.resize(800, 600);
    window.show();

    return app.exec();
  } catch (const std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
