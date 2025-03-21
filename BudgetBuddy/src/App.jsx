import React from 'react'
import {BrowserRouter,Routes,Route} from "react-router-dom"
import LandingPage from './pages/Landing';
import Authenticate from './pages/Authenticate';
import Userhome from './pages/Userhome';
import Profile from './pages/Profile';
function App() {
  return (
   <BrowserRouter>
   <Routes>
    <Route path="/" element={<LandingPage/>}/>
    <Route path="/authenticate" element={<Authenticate/>}/>
    <Route path="/userhome" element={<Userhome/>}/>
    <Route path="/profile" element={<Profile/>}/>
   </Routes>
   </BrowserRouter>
  )
}

export default App;