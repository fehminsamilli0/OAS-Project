<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Mail\WelcomeMail;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{

    /*  Userlərin siyahısını api-ə göndərir */

    public function index(){
//        if (Auth::user()->admin == 1) {
        $users = User::all();
        return response() -> json([
            'status' => 200,
            'users' => $users,
        ]);
    }

    /* Admin Tərəfindən istifadəçilər qeydiyyata alınır */

    public function register(Request $request){

        $request->validate([
            'name' => 'required|string|unique:users',
            'email' => 'required|string|unique:users',
        ]);

        /* İstifadəçiyə random şifrə generasiya olunur  */

        $random = str_shuffle('abcdefghjklmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ234567890');
        $password = substr($random, 0, 10);


        /* Gələn inputlar db-ə yazılır */

        $user = new User([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'admin' => $request->input('admin',0),
            'password' => Hash::make($password)

        ]);

        /* İstifadəçi usarname və şifrə WelcomeMail controllerdə istifadə üçün dataya mənimsədilir */

        $data = [
            'password' => $password,
            'name'=>$user['name']
        ];
        $user->save();

        /* İstifadəçiyə Şəxsi Token verilir */

        $token = $user->createToken('mytoken')->plainTextToken;


        /* İstifadəçiyə mailin göndərilməsi */

        Mail::to($request->input('email'))->send(new WelcomeMail($data));

        return response(['status' => 201]);

    }

    /* İstifadəçinin sistemdən çıxışı */

    public function logout(Request $request){
        auth()->user()->tokens()->delete();

        return response(['message'=>'User Logout Successfully'], 204);

    }

    /* İstifadəçinin silinməsi */

    public function delete($id) {

        $users = User::findOrFail($id);
        if($users->admin == 0){
            $users->delete();
            return response(['message'=>'User Deleted Successfully'], 202);
        }
        else{
            return response(['message'=>'User Can Not Be Deleted'], 401);
        }

    }

    /* İstifadəçinin sistemə girişi */

    public function login(Request $request)
    {
        $fields =$request->validate([
            'name' => 'required',
            'password'=> 'required|string'
        ]);

        /* Username-in yoxlanması */
        $user = User::where('name',$fields['name'])->first();

        /* Şifrənin yoxlanması */
        if (!$user || !Hash::check($fields['password'],$user->password)){
            return response(['message'=>'Bad creds'], 401);
        }
        /* Yoxlanışdan keçirsə access token verir */

        $token = $user->createToken('mytoken')->plainTextToken;

        $response = [
            'user'=>$user,
            'token'=>$token
        ];

        return response(['response' => $response,'status' => 200]);

    }

}
