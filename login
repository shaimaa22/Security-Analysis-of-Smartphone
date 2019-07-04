package com.grad.encryption.Fragments;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.grad.encryption.MainActivity;
import com.grad.encryption.R;

public class Login extends Fragment {
    View RootView;
    EditText Pass;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return RootView=inflater.inflate(R.layout.fragment_login,container,false);
    }

    @Override
    public void onActivityCreated(@Nullable Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
         Pass = RootView.findViewById(R.id.password);
        final TextView Submit = RootView.findViewById(R.id.login);
        Submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(Pass.getText().toString().equals(MainActivity.Password))
                {
                    getActivity().getSupportFragmentManager().beginTransaction().replace(R.id.main_container,new File_Explorer_Fragment()).commit();
                    Toast.makeText(getContext(),"Access Granted",Toast.LENGTH_SHORT).show();
                }
                else
                {
                    Toast.makeText(getContext(),"Wrong Password",Toast.LENGTH_SHORT).show();
                }
            }
        });

    }
}
