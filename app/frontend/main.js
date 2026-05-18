const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const path = require('path')
const fs = require('fs')

function createWindow () {
  const win = new BrowserWindow({
    width: 1100,
    height: 760,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })
  win.loadFile('index.html')
}

app.whenReady().then(() => {
  createWindow()
  ipcMain.handle('pick-file', async () => {
    const res = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [{ name: 'APK/SO', extensions: ['apk', 'so'] }]
    })
    if (res.canceled || res.filePaths.length === 0) return null
    const file = res.filePaths[0]
    return { file, size: fs.statSync(file).size }
  })
})
